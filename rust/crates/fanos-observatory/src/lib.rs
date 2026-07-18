//! # fanos-observatory — the terminal Coherence Observatory
//!
//! `fanos-monitor` renders the network's **coherence self-model** (`Φ/P/R/Δ`, the collective-subject
//! band, cascade early-warning, the Fano syndrome, healing) as a native terminal UI for a human
//! operator — no browser, minimal resources, embedded-friendly — while `--json` emits the same
//! [`CoherenceSnapshot`](fanos_telemetry::CoherenceSnapshot) for an agent. One self-model, two audiences.
//!
//! The design mirrors the platform's sans-I/O monism (*one engine, many drivers*): the UI depends only
//! on the [`SnapshotSource`] seam, so the demo [`ScenarioSource`] (a real DIAKRISIS `PurityDynamics`
//! cell the operator drives) can be swapped for a live node-telemetry feed without touching a line of
//! the rendering. Everything the operator sees is produced by the shipped telemetry code.

pub mod app;
pub mod source;
pub mod ui;

pub use app::App;
pub use source::{Control, ScenarioSource, SnapshotSource};
