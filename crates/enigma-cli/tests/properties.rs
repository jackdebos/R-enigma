//! Property-style end-to-end tests for the `transform` path (`docs/protocol.md` §3.2, §7).
//!
//! Every property drives the real `enigma` binary over its stdio transport and asserts on
//! the emitted JSONL events; the engine is never called directly. A small fixed-seed
//! generator keeps each case reproducible, so a failure can be replayed from the printed
//! configuration without adding an external property-testing dependency to the workspace.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const ROTORS: [&str; 5] = ["I", "II", "III", "IV", "V"];

/// A tiny SplitMix64 generator: deterministic, dependency-free, and good enough to sample
/// valid configurations and texts. Each test uses its own fixed seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn symbol(&mut self) -> char {
        (b'A' + self.below(26) as u8) as char
    }

    fn text(&mut self, max_len: usize) -> String {
        let len = 1 + self.below(max_len);
        (0..len).map(|_| self.symbol()).collect()
    }

    /// A valid, disjoint plugboard: zero to five pairs drawn from a shuffled alphabet.
    fn plugboard(&mut self) -> Vec<Value> {
        let pairs = self.below(6);
        let mut pool: Vec<char> = ('A'..='Z').collect();
        for i in (1..pool.len()).rev() {
            let j = self.below(i + 1);
            pool.swap(i, j);
        }
        (0..pairs)
            .map(|i| json!([pool[2 * i].to_string(), pool[2 * i + 1].to_string()]))
            .collect()
    }
}

/// A random but valid `enigma-i` setting: distinct rotor order, positions, rings, plugboard.
fn random_setting(rng: &mut Rng) -> ([&'static str; 3], [char; 3], [char; 3], Vec<Value>) {
    let mut order = ROTORS;
    for i in (1..order.len()).rev() {
        let j = rng.below(i + 1);
        order.swap(i, j);
    }
    let rotors = [order[0], order[1], order[2]];
    let rings = [rng.symbol(), rng.symbol(), rng.symbol()];
    let positions = [rng.symbol(), rng.symbol(), rng.symbol()];
    (rotors, rings, positions, rng.plugboard())
}

fn enigma_i_request(
    rotors: [&str; 3],
    rings: [char; 3],
    positions: [char; 3],
    plugboard: &[Value],
    text: &str,
    direction: &str,
) -> Value {
    json!({
        "protocol_version": 1,
        "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
        "job": {
            "kind": "transform",
            "configuration": {
                "slots": [
                    {"id": "reflector", "wheel": "B", "position": "A", "ring": "A"},
                    {"id": "left", "wheel": rotors[0], "position": positions[0].to_string(), "ring": rings[0].to_string()},
                    {"id": "middle", "wheel": rotors[1], "position": positions[1].to_string(), "ring": rings[1].to_string()},
                    {"id": "right", "wheel": rotors[2], "position": positions[2].to_string(), "ring": rings[2].to_string()}
                ],
                "plugboard": plugboard
            },
            "text": text,
            "direction": direction
        }
    })
}

/// A one-rotor, reflector-free custom machine: the directional (non-reciprocal) topology.
fn no_reflector_request(text: &str, direction: &str) -> Value {
    json!({
        "protocol_version": 1,
        "machine": {"definition": {"kind": "custom", "value": {
            "alphabet": ["A", "B", "C", "D"],
            "wheels": [{"name": "rotor", "wiring": ["B", "A", "D", "C"], "turnovers": ["B"]}],
            "slots": [{"id": "fast", "role": "rotor", "movement": "movable", "allowed_wheels": ["rotor"]}],
            "stepping": {"rules": [{"when": {"always": true}, "advance": ["fast"]}]}
        }}},
        "job": {
            "kind": "transform",
            "configuration": {
                "slots": [{"id": "fast", "wheel": "rotor", "position": "B", "ring": "A"}],
                "plugboard": []
            },
            "text": text,
            "direction": direction
        }
    })
}

fn run(request: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--events", "-", "--request", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the enigma binary");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(request.to_string().as_bytes())
        .expect("failed to write the request to stdin");
    child.wait_with_output().expect("failed to collect output")
}

/// Runs one transform and returns the single `output` event; fails on any error event.
fn transform(request: &Value) -> String {
    let output = run(request);
    assert!(
        output.status.success(),
        "transform failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is valid UTF-8");
    let mut result = None;
    for line in stdout.lines() {
        let event: Value = serde_json::from_str(line).expect("each stdout line is one JSON object");
        match event["event"].as_str() {
            Some("output") => {
                result = Some(
                    event["output"]
                        .as_str()
                        .expect("output is a string")
                        .to_string(),
                )
            }
            Some("error") => panic!("unexpected error event: {event}"),
            _ => {}
        }
    }
    result.expect("a successful transform emits an output event")
}

#[test]
fn reflector_transform_preserves_alphabet_and_length() {
    let mut rng = Rng::new(0x5EED_0001);
    for _ in 0..24 {
        let (rotors, rings, positions, plugboard) = random_setting(&mut rng);
        let text = rng.text(48);
        let request = enigma_i_request(rotors, rings, positions, &plugboard, &text, "encrypt");
        let out = transform(&request);
        assert_eq!(
            out.chars().count(),
            text.chars().count(),
            "length changed for {text:?} -> {out:?} under {rotors:?} {positions:?}"
        );
        assert!(
            out.chars().all(|c| c.is_ascii_uppercase()),
            "output left the alphabet: {out:?}"
        );
    }
}

#[test]
fn reflector_transform_is_an_involution() {
    let mut rng = Rng::new(0x5EED_0002);
    for _ in 0..24 {
        let (rotors, rings, positions, plugboard) = random_setting(&mut rng);
        let text = rng.text(48);
        let encipher = enigma_i_request(rotors, rings, positions, &plugboard, &text, "encrypt");
        let cipher = transform(&encipher);
        // A reflector makes the traversal reciprocal, so applying the same key again
        // restores the plaintext.
        let decipher = enigma_i_request(rotors, rings, positions, &plugboard, &cipher, "encrypt");
        let back = transform(&decipher);
        assert_eq!(
            back, text,
            "not involutive for {rotors:?} {rings:?} {positions:?}"
        );
    }
}

#[test]
fn reflector_transform_has_no_self_encryption() {
    let mut rng = Rng::new(0x5EED_0003);
    for _ in 0..24 {
        let (rotors, rings, positions, plugboard) = random_setting(&mut rng);
        let text = rng.text(48);
        let request = enigma_i_request(rotors, rings, positions, &plugboard, &text, "encrypt");
        let out = transform(&request);
        for (input, output) in text.chars().zip(out.chars()) {
            assert_ne!(
                input, output,
                "a reflectored letter encrypted to itself: {text:?} -> {out:?} under {rotors:?} {positions:?}"
            );
        }
    }
}

#[test]
fn reflector_encrypt_and_decrypt_agree() {
    let mut rng = Rng::new(0x5EED_0004);
    for _ in 0..24 {
        let (rotors, rings, positions, plugboard) = random_setting(&mut rng);
        let text = rng.text(48);
        let encipher = enigma_i_request(rotors, rings, positions, &plugboard, &text, "encrypt");
        let decipher = enigma_i_request(rotors, rings, positions, &plugboard, &text, "decrypt");
        assert_eq!(
            transform(&encipher),
            transform(&decipher),
            "direction changed the output under a reflector: {rotors:?} {positions:?}"
        );
    }
}

#[test]
fn no_reflector_decrypt_inverts_encrypt() {
    let mut rng = Rng::new(0x5EED_0005);
    for _ in 0..24 {
        let len = 1 + rng.below(24);
        let text: String = (0..len)
            .map(|_| (b'A' + rng.below(4) as u8) as char)
            .collect();

        let cipher = transform(&no_reflector_request(&text, "encrypt"));
        let plain = transform(&no_reflector_request(&cipher, "decrypt"));
        assert_eq!(plain, text, "encrypt/decrypt did not round-trip {text:?}");

        let cipher_rev = transform(&no_reflector_request(&text, "decrypt"));
        let plain_rev = transform(&no_reflector_request(&cipher_rev, "encrypt"));
        assert_eq!(
            plain_rev, text,
            "decrypt/encrypt did not round-trip {text:?}"
        );
    }
}

#[test]
fn transform_is_deterministic() {
    let mut rng = Rng::new(0x5EED_0006);
    for _ in 0..16 {
        let (rotors, rings, positions, plugboard) = random_setting(&mut rng);
        let text = rng.text(32);
        let request = enigma_i_request(rotors, rings, positions, &plugboard, &text, "encrypt");
        assert_eq!(
            transform(&request),
            transform(&request),
            "the same request produced two different outputs"
        );
    }
}
