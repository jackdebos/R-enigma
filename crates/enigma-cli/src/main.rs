//! Command-line client.
//!
//! Stage 1 speaks the protocol over `stdin`/`stdout` (see `docs/protocol.md` §2). This
//! binary is a thin shell: it must contain no cryptanalytic logic, so that the same
//! engine can be driven by the TUI (Stage 2), the local web client (Stage 2) and the
//! test harness without divergence.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        None => {
            eprintln!("enigma {}", env!("CARGO_PKG_VERSION"));
            eprintln!("protocol version {}", enigma_core::PROTOCOL_VERSION);
            eprintln!();
            eprintln!("Usage: enigma <request.json>");
            eprintln!();
            eprintln!("Not implemented yet: the request parser lands in task 7.");
            eprintln!("See docs/protocol.md for the contract and odd/tasks/enigma-engine.md for the plan.");
            ExitCode::from(2)
        }
        Some(_) => {
            eprintln!("error: request handling is not implemented yet (task 7)");
            ExitCode::FAILURE
        }
    }
}
