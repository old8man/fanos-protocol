//! A **remote** snapshot source: a deployed node, read over its control socket.
//!
//! The gap this closes is one this crate's own module doc has named since it was written — "a remote source,
//! subscribing to a running node's telemetry stream, implements the same [`SnapshotSource`] trait and drops in
//! behind this one". Until now `fanos-monitor` had two sources, a scripted [`ScenarioSource`](crate::ScenarioSource)
//! and a cell of production engines under the simulator, and **neither was a node anyone deployed**. An operator
//! tool that cannot observe the thing it exists for is a demo.
//!
//! It reads `fanos status coherence` off the node's Unix control socket. That verb serves the frame's canonical
//! `Wire` bytes as hex on one line, so this decodes exactly what the node holds rather than scraping a rendering
//! meant for a person — the human form stays free to change, which it would not be if a monitor parsed it.
//!
//! **Read-only, and that is not an omission.** [`SnapshotSource::control`] can crash and heal nodes in the
//! simulated source, because there the cell is the operator's to break. A deployed node's controls are its
//! configuration and its `shutdown` verb, both reviewable and both outside a monitor's remit: a dashboard that
//! can fault production is a dashboard whose bugs fault production.

use std::path::PathBuf;

use fanos_telemetry::{CoherenceFrame, CoherenceSnapshot};

use crate::source::{Control, SnapshotSource};

/// How many points a Fano cell holds — the denominator of the pressure gauge.
const CELL_POINTS: f64 = 7.0;

/// The frame reported before anything has been read. Every measure zero — see [`SnapshotSource::snapshot`]
/// for why that is the least-bad of the available lies and where the truth is carried instead.
const UNREAD: CoherenceFrame = CoherenceFrame {
    cell_id: fanos_telemetry::CellId([0; 16]),
    epoch: 0,
    syndrome: 0,
    verdict: 0,
    phi: 0.0,
    purity: 0.0,
    reflection: 0.0,
    mean_r: 0.0,
    gap: 0.0,
    forecast: 0,
    heal_seq: 0,
};

/// A deployed node, observed over its control socket.
pub struct RemoteNodeSource {
    socket: PathBuf,
    label: String,
    /// The last frame the node reported, or `None` before the first successful read.
    frame: Option<CoherenceFrame>,
    degraded: u8,
    alive: u16,
    /// Why the last read produced nothing, for the header. An operator staring at a still dashboard must be
    /// able to tell "the node is healthy and quiet" from "I have not reached it since it started".
    status: String,
}

impl RemoteNodeSource {
    /// A source reading the node whose state lives in `data`.
    #[must_use]
    pub fn new(data: &std::path::Path) -> Self {
        let socket = fanos_node::admin::socket_path(data);
        Self {
            label: format!("remote · {}", socket.display()),
            socket,
            frame: None,
            degraded: 0,
            alive: 0,
            status: "not yet read".to_owned(),
        }
    }

    /// Parse the `coherence` body: the `wire` line is authoritative, the rest is for people.
    fn absorb(&mut self, body: &str) {
        let mut degraded = 0u8;
        let mut alive = 0u16;
        for line in body.lines() {
            let Some((key, value)) = line.split_once(':') else { continue };
            let value = value.trim();
            match key.trim() {
                "wire" => {
                    let bytes: Option<Vec<u8>> = (0..value.len() / 2)
                        .map(|i| u8::from_str_radix(value.get(i * 2..i * 2 + 2)?, 16).ok())
                        .collect();
                    match bytes.as_deref().and_then(CoherenceFrame::decode) {
                        Some(f) => {
                            self.frame = Some(f);
                            "live".clone_into(&mut self.status);
                        }
                        // A frame this build cannot decode is itself a finding — the node is on a release
                        // whose frame layout this monitor does not know — so it is reported, not ignored.
                        None => "node frame did not decode (version skew?)".clone_into(&mut self.status),
                    }
                }
                "alive" => alive = value.parse().unwrap_or(0),
                "degraded" => {
                    // Rendered as `points 1, 4` or `none — …`; the mask is rebuilt from the set.
                    for tok in value.trim_start_matches("points").split(',') {
                        if let Ok(p) = tok.trim().parse::<u32>() {
                            degraded |= 1u8 << (p % 8);
                        }
                    }
                }
                _ => {}
            }
        }
        self.degraded = degraded;
        self.alive = alive;
    }
}

impl SnapshotSource for RemoteNodeSource {
    fn tick(&mut self) {
        match fanos_node::admin::ask_blocking(&self.socket, "coherence") {
            Ok(Some(body)) => self.absorb(&body),
            // The distinction the whole `Ok(None)` arm exists for: a stopped node is not a broken one, and a
            // monitor that showed the same thing for both would send its operator looking in the wrong place.
            Ok(None) => "node not running (no socket)".clone_into(&mut self.status),
            Err(e) => self.status = format!("socket error: {e}"),
        }
        self.label = format!("remote · {} · {}", self.socket.display(), self.status);
    }

    fn snapshot(&self) -> CoherenceSnapshot {
        // Before the first successful read there is no frame, and the trait has no way to say so — it returns
        // a snapshot, not an option. A zeroed frame is the only thing available and it renders as **total
        // collapse**, which is the worst possible lie for a monitor to tell: the operator would be looking at
        // a catastrophe that is really just an unconnected socket.
        //
        // So the absence is carried where the reader will see it instead — `label()` is shown in the header
        // and always ends with the status, so "not yet read" sits beside the zeros that it explains. Fixing
        // this properly means the trait admitting "no reading", which is the same shape as the load sensor's
        // `Option` and worth doing when the UI can act on it.
        self.frame.as_ref().map_or_else(
            || CoherenceSnapshot::from_frame(&UNREAD),
            CoherenceSnapshot::from_frame,
        )
    }

    // Deliberately inert — see the module doc. A monitor does not fault production.
    fn control(&mut self, _op: Control) {}

    fn label(&self) -> &str {
        &self.label
    }

    fn pressure(&self) -> f64 {
        // The same fold the simulated live source uses: the degraded fraction of the cell. Derived from the
        // footprint rather than invented, so the two sources' gauges mean the same thing.
        f64::from(self.degraded.count_ones()) / CELL_POINTS
    }

    fn degraded(&self) -> u8 {
        self.degraded
    }

    fn reading(&self) -> Result<(), String> {
        if self.frame.is_some() { Ok(()) } else { Err(self.status.clone()) }
    }
}

/// What the last read produced, for a header that must not imply liveness it does not have.
impl RemoteNodeSource {
    /// A short status line: `live`, or why not.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The exact shape `fanos status coherence` emits, including the human lines the parser must ignore.
    fn body(wire: &str, degraded: &str) -> String {
        format!(
            "wire           : {wire}\n\
             alive          : 5\n\
             degraded       : {degraded}\n\
             epoch          : 12\n\
             phi            : 0.875\n\
             syndrome       : 4 (point 3)\n"
        )
    }

    #[test]
    fn the_frame_comes_from_the_canonical_bytes_and_not_from_the_human_render() {
        // The whole reason the verb serves a `wire` line: a monitor that scraped `phi            : 0.875`
        // would freeze the rendering's column widths into a protocol, and the render exists to be read by
        // people. Proven by feeding a body whose human lines DISAGREE with its bytes — the bytes must win.
        let frame = CoherenceFrame {
            cell_id: fanos_telemetry::CellId([9; 16]),
            epoch: 77,
            syndrome: 2,
            verdict: 1,
            phi: 0.25,
            purity: 0.5,
            reflection: 0.125,
            mean_r: 0.5,
            gap: 0.0625,
            forecast: -4,
            heal_seq: 3,
        };
        let hex = frame.encode().iter().fold(String::new(), |mut a, b| {
            use core::fmt::Write as _;
            let _ = write!(a, "{b:02x}");
            a
        });

        let mut src = RemoteNodeSource::new(std::path::Path::new("/nonexistent"));
        src.absorb(&body(&hex, "points 1, 4"));
        assert_eq!(src.frame, Some(frame), "the canonical bytes decode to exactly what the node holds");
        assert_eq!(src.status(), "live");
    }

    #[test]
    fn the_footprint_is_a_set_of_points_not_the_syndrome() {
        // The reason `Notification::Liveness` exists at all: the frame's 3-bit syndrome localizes ONE fault,
        // and a monitor's node map must show all of them. Two points down, one syndrome — deriving the map
        // from the syndrome would draw one.
        let mut src = RemoteNodeSource::new(std::path::Path::new("/nonexistent"));
        src.absorb(&body("", "points 1, 4"));
        assert_eq!(src.degraded(), 0b0001_0010, "points 1 and 4, both of them");
        assert_eq!(src.alive, 5);
        // The pressure gauge is the degraded fraction — the same fold the simulated source uses, so the two
        // sources' gauges mean the same thing rather than merely looking alike.
        assert!((src.pressure() - 2.0 / 7.0).abs() < 1e-9, "2 of 7 down: {}", src.pressure());

        src.absorb(&body("", "none — every point fresh"));
        assert_eq!(src.degraded(), 0, "a healthy cell has an empty footprint, not a parsed word");
        assert!(src.pressure().abs() < 1e-9);
    }

    #[test]
    fn a_frame_this_build_cannot_decode_is_reported_rather_than_ignored() {
        // Version skew reaching the monitor: the node is on a release whose frame layout this build does not
        // know. Silently keeping the previous reading would show a stale cell as a live one.
        let mut src = RemoteNodeSource::new(std::path::Path::new("/nonexistent"));
        src.absorb(&body("deadbeef", "none"));
        assert!(src.status().contains("did not decode"), "got {}", src.status());
        assert!(src.frame.is_none(), "and no frame is invented from the human lines");
    }

    #[test]
    fn an_unreached_node_never_reports_a_healthy_cell() {
        // The finding this guard exists for, measured on a real run before it existed: with no node running,
        // `fanos-monitor --json` printed `"alarm":"healthy","faulted":false`. The trait returns a snapshot
        // rather than an option, so an unread source must return *something*, and all-zeros folds to healthy.
        // A monitor reporting the cell healthy BECAUSE it could not reach it fails in the one direction that
        // hides a failure rather than raising a false one, and an agent reading the JSON cannot see through it.
        let mut src = RemoteNodeSource::new(std::path::Path::new("/nonexistent/fanos"));
        src.tick();
        assert!(src.reading().is_err(), "an unreached node must not claim to be a reading");

        // And the placeholder really does look healthy — so the guard is load-bearing, not belt-and-braces.
        let json = src.snapshot().to_json();
        assert!(
            json.contains("\"alarm\":\"healthy\""),
            "the premise: the zeros fold to `healthy`, which is why they must never be printed: {json}"
        );

        // Once a frame arrives it IS a reading.
        let frame = CoherenceFrame { epoch: 3, phi: 0.5, ..UNREAD };
        let hex = frame.encode().iter().fold(String::new(), |mut a, b| {
            use core::fmt::Write as _;
            let _ = write!(a, "{b:02x}");
            a
        });
        src.absorb(&body(&hex, "none"));
        assert!(src.reading().is_ok(), "a decoded frame is a reading");
    }

    #[test]
    fn a_stopped_node_is_not_a_broken_one() {
        // The first thing an operator needs to know, and the distinction `ask_blocking`'s `Ok(None)` carries.
        let mut src = RemoteNodeSource::new(std::path::Path::new("/nonexistent/fanos"));
        src.tick();
        assert!(src.status().contains("not running"), "got {}", src.status());
        // And the header says so, because the zeros below it would otherwise read as a collapsed cell.
        assert!(src.label().contains("not running"), "the status must reach the header: {}", src.label());
    }
}
