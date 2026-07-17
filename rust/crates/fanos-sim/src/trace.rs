//! A structured, inspectable event trace — the simulator's log for debugging the protocol.
//!
//! When enabled, the simulator records a timestamped line for every event it dispatches and
//! every effect it performs (deliveries, drops, timers, sends, notifications). The result is a
//! causal, deterministic log that can be dumped, filtered, or diffed between runs — the tool
//! for debugging protocol behaviour at all levels.

/// A timestamped, human-readable event log.
#[derive(Clone, Debug, Default)]
pub struct Trace {
    records: Vec<(u64, String)>,
    enabled: bool,
}

impl Trace {
    /// A new, disabled trace (recording is opt-in to keep default runs fast).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Turn recording on or off.
    pub fn enable(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Whether recording is on.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a line at `time_ns` (no-op when disabled).
    pub(crate) fn record(&mut self, time_ns: u64, line: impl Into<String>) {
        if self.enabled {
            self.records.push((time_ns, line.into()));
        }
    }

    /// Number of recorded lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the trace is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The raw log lines (without timestamps).
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|(_, line)| line.as_str())
    }

    /// Lines containing `pattern` (a simple substring filter for focused debugging).
    #[must_use]
    pub fn grep(&self, pattern: &str) -> Vec<&str> {
        self.lines().filter(|l| l.contains(pattern)).collect()
    }

    /// The full log, one `[      t ms] line` per entry.
    #[must_use]
    pub fn dump(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (t, line) in &self.records {
            let ms = *t as f64 / 1_000_000.0;
            let _ = writeln!(out, "[{ms:10.3} ms] {line}");
        }
        out
    }
}

/// Format a coordinate triple compactly, e.g. `[1:0:0]`.
#[must_use]
pub fn fmt_coord(coord: fanos_runtime::Triple) -> String {
    let [x, y, z] = coord;
    format!("[{x}:{y}:{z}]")
}
