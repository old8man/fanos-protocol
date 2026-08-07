//! Where a running node learns that it should stop.
//!
//! A node's clean stop is not free: it persists its store before closing the endpoint (#178), and that
//! ordering is the whole point of the work. Whether the drain runs at all depends on something upstream of
//! it — **which signals the process actually handles** — and that is a separate question from whether the
//! drain is correct.
//!
//! `tokio::signal::ctrl_c()` covers an interactive Ctrl-C and nothing else. Every *orchestrated* stop —
//! `systemctl stop`, a container runtime, a supervisor, a rolling restart — sends `SIGTERM`, whose default
//! disposition is immediate termination. A binary listening only for `SIGINT` therefore skips its drain on
//! exactly the stops a deployment performs, while passing every interactive test a developer runs by hand.

use tracing::{info, warn};

/// The signals this binary treats as "stop cleanly".
///
/// This list exists to be **read by a guard**, not only by a reader: [`render_systemd_unit`] writes a
/// `KillSignal=` and a test asserts that signal is a member here. The supervisor's choice and the binary's
/// handler set are each perfectly plausible in isolation and only wrong *together*, so checking either half
/// alone cannot catch the mismatch — the guard has to span the join.
///
/// [`render_systemd_unit`]: crate::setup::render_systemd_unit
pub const HANDLED_STOP_SIGNALS: &[&str] = &["SIGINT", "SIGTERM"];

/// Completes when the operator or the supervisor asks this process to stop, naming the signal that arrived.
///
/// Naming it is not decoration: an operator debugging a restart loop needs to know whether the node was
/// interrupted at a terminal or reaped by its supervisor, and the two have different causes.
pub async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    r = tokio::signal::ctrl_c() => {
                        if let Err(e) = r {
                            warn!(error = %e, "the interrupt handler failed; stopping anyway");
                        }
                        info!(signal = "SIGINT", "stop requested");
                    }
                    _ = term.recv() => info!(signal = "SIGTERM", "stop requested"),
                }
            }
            Err(e) => {
                // Fail *loud and degraded*, never silent: the node still stops on Ctrl-C, but an operator
                // must know that `systemctl stop` will now kill it mid-drain rather than let it persist.
                warn!(
                    error = %e,
                    "could not install a SIGTERM handler: an orchestrated stop will terminate this node \
                     without draining, so state written since the last snapshot will be lost"
                );
                let _ = tokio::signal::ctrl_c().await;
                info!(signal = "SIGINT", "stop requested");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!(signal = "SIGINT", "stop requested");
    }
}
