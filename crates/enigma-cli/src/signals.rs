//! Platform interrupt/termination signals as a cooperative attack cancellation.
//!
//! The handler only feeds a sticky flag; it never evaluates or writes events. The first
//! signal requests the same safe stop as `--cancel-file`; any later one exits at once
//! with code 130, without a terminal-event guarantee. Installation is deferred until a
//! hill_climb/partial_exhaustion attack is about to start, so earlier phases keep the
//! default signal behavior.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Exit code for a second signal, conventionally 128 + SIGINT.
const HARD_EXIT: i32 = 130;

static REQUESTED: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();

/// What the handler does for one delivered signal.
#[derive(Debug, PartialEq, Eq)]
enum SignalAction {
    Cancel,
    Exit(i32),
}

/// Counts one signal: the first raises the sticky flag, every later one exits.
fn on_signal(count: &AtomicUsize, requested: &AtomicBool) -> SignalAction {
    if count.fetch_add(1, Ordering::Relaxed) == 0 {
        requested.store(true, Ordering::Relaxed);
        SignalAction::Cancel
    } else {
        SignalAction::Exit(HARD_EXIT)
    }
}

/// Installs the process handler at most once and returns the flag it feeds.
pub(crate) fn install() -> Result<&'static AtomicBool, String> {
    let installed = INSTALLED.get_or_init(|| {
        ctrlc::set_handler(|| {
            if let SignalAction::Exit(code) = on_signal(&COUNT, &REQUESTED) {
                std::process::exit(code);
            }
        })
        .map_err(|error| error.to_string())
    });
    installed.clone().map(|()| &REQUESTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_signal_cancels_and_later_signals_exit() {
        let (count, requested) = (AtomicUsize::new(0), AtomicBool::new(false));
        assert_eq!(on_signal(&count, &requested), SignalAction::Cancel);
        assert!(requested.load(Ordering::Relaxed));
        for _ in 0..2 {
            assert_eq!(on_signal(&count, &requested), SignalAction::Exit(130));
            assert!(requested.load(Ordering::Relaxed));
        }
    }
}
