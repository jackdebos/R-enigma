//! # enigma-core
//!
//! The compute core of the project: a *universal* Enigma model, the scoring measures
//! and the cryptanalysis passes. It performs no I/O and knows nothing about clients.
//!
//! The contract this crate must satisfy is `docs/protocol.md`. The plan and the task
//! breakdown live in `odd/tasks/enigma-engine.md`.
//!
//! ## Design constraints
//!
//! These are not stylistic preferences; they come from the measured behaviour of the
//! reference implementation (`bomm`, 8 ns per decrypted letter):
//!
//! 1. **No machine-specific code paths.** Every historical machine is configuration
//!    data (slots, wheels, turnover sets, plugboard) over one generic engine. Stepping
//!    is a *rule*, not a parameter, because the Zählwerk machines do not fit
//!    "a notch advances the next wheel".
//! 2. **No external calls in the inner loop.** Decryption and scoring are fused, and the
//!    scrambler wiring for a given wheel order is precomputed once per candidate key
//!    position and reused across all decrypts at that position.
//! 3. **Determinism is contractual.** Scoring must be independent per candidate, with no
//!    unordered reductions, so that the CPU and (Stage 4) GPU backends agree exactly.
//!
//! ## Module layout (target)
//!
//! | Module | Responsibility | Task |
//! | --- | --- | --- |
//! | [`letter`] | Alphabet, letters, letter masks | 4 |
//! | `wiring` | Permutations over the alphabet | 4 |
//! | `wheel` | Wheels: wiring + turnover set | 4 |
//! | `stepping` | Stepping rules (`stepping`, `odometer`, `none`, `cog`) | 4 |
//! | `machine` | Slots + wheels + plugboard + reflector | 4 |
//! | `presets` | Enigma I, M3, M4 as data | 5 |
//! | `request` | Job request model (superset of `bomm`'s query schema) | 7 |
//! | `measure` | IC, Sinkov n-gram, entropy, chi-squared | 8 |
//! | `passes` | Hill climbing, partial exhaustion, reswapping | 9 |
//! | `event` | Protocol event stream types | 10 |
//! | `checkpoint` | Durable state and resume | 11 |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Protocol version implemented by this crate.
///
/// Must match `docs/protocol.md` §10. A breaking change to the protocol bumps this.
pub const PROTOCOL_VERSION: u32 = 1;
