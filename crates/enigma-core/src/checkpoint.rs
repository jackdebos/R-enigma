//! Checkpoint identity for resumable HC/PE attacks (protocol §6.4).
//!
//! The identity is a SHA-256 digest over the canonical request, the catalog content of
//! a bundled definition and the exact bytes of every loaded resource, so any drift in
//! what the search would do rejects an old checkpoint before work.

use crate::strict_json::StrictValue;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

const IDENTITY_DOMAIN: &[u8] = b"enigma-checkpoint-identity/1\n";

/// SHA-256 identity digest binding a checkpoint to one search request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointIdentity([u8; 32]);

impl CheckpointIdentity {
    /// Raw digest bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hexadecimal, 64 digits.
impl fmt::Display for CheckpointIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Why an identity could not be computed; requests are validated before this point.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointIdentityError {
    /// The request is not strict JSON.
    InvalidRequest,
    /// The request names a bundled definition the engine does not ship.
    UnknownBundledDefinition(String),
}

impl fmt::Display for CheckpointIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("request is not strict JSON"),
            Self::UnknownBundledDefinition(id) => {
                write!(f, "bundled definition {id:?} is unavailable")
            }
        }
    }
}

impl std::error::Error for CheckpointIdentityError {}

/// Computes the protocol §6.4 identity of a validated request and its loaded resources.
///
/// `resources` maps each measure ID to the exact text loaded for it.
pub fn checkpoint_identity(
    request_json: &str,
    resources: &BTreeMap<String, String>,
) -> Result<CheckpointIdentity, CheckpointIdentityError> {
    let mut deserializer = serde_json::Deserializer::from_str(request_json);
    let request = StrictValue::deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value.into_value()))
        .map_err(|_| CheckpointIdentityError::InvalidRequest)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(request.to_string().as_bytes());
    hasher.update(b"\n");
    let definition = &request["machine"]["definition"];
    if definition["kind"] == "bundled" {
        let id = definition["id"].as_str().unwrap_or_default();
        let catalog = crate::definition::bundled_catalog_json(id)
            .ok_or_else(|| CheckpointIdentityError::UnknownBundledDefinition(id.to_owned()))?;
        hasher.update(catalog.as_bytes());
        hasher.update(b"\n");
    }
    for (id, content) in resources {
        hasher.update(id.as_bytes());
        hasher.update(format!("\n{}\n", content.len()).as_bytes());
        hasher.update(content.as_bytes());
    }
    Ok(CheckpointIdentity(hasher.finish()))
}

/// Streaming SHA-256 (FIPS 180-4).
pub(crate) struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            let take = (64 - self.filled).min(bytes.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == 64 {
                self.compress();
                self.filled = 0;
            }
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8);
        self.block[self.filled] = 0x80;
        self.block[self.filled + 1..].fill(0);
        if self.filled >= 56 {
            self.compress();
            self.block.fill(0);
        }
        self.block[56..].copy_from_slice(&bits.to_be_bytes());
        self.compress();
        let mut digest = [0; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self) {
        let mut w = [0u32; 64];
        for (word, chunk) in w.iter_mut().zip(self.block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex(&hasher.finish())
    }

    #[test]
    fn sha256_matches_fips_180_4_vectors_and_padding_boundaries() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        for (length, expected) in [
            (
                55,
                "eb2c86e932179f4ba13fe8715a26124b77d6bad290b9b4c1cc140cf633300c19",
            ),
            (
                56,
                "a5fc6e203a4c2b657d0d153885932414b2ffc6a93f0f8bf8b3183315e5a7212c",
            ),
            (
                63,
                "94e419fabac7f930810f9636354042f8c1426d2f834d4ab65c93dc1e69326b13",
            ),
            (
                64,
                "a0fab1377f49a759b57f63318262ebe89fabfc990e8e93ceac2984561482b9d4",
            ),
            (
                65,
                "74b128f30cf83de43ddf4aafc40c7b50a7443d3c73a89a7cfca17e15e43d51ab",
            ),
            (
                119,
                "68297a9eb141ce16bbc0847da1c0c48e2858704feaa13993bde29f87a198a6e1",
            ),
            (
                120,
                "392add47fbaa8197a874ebe770a947a26dd6f2becce5f64688cc4d18c9da93bd",
            ),
        ] {
            assert_eq!(sha256(&vec![b'b'; length]), expected, "length {length}");
        }
    }

    #[test]
    fn sha256_streaming_split_points_do_not_change_the_digest() {
        let message: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let whole = sha256(&message);
        for split in [0, 1, 55, 63, 64, 65, 128, 299, 300] {
            let mut hasher = Sha256::new();
            hasher.update(&message[..split]);
            hasher.update(&message[split..]);
            assert_eq!(hex(&hasher.finish()), whole, "split {split}");
        }
    }

    fn request() -> serde_json::Value {
        json!({"protocol_version": 1,
            "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
            "text": "ABCDEF",
            "job": {"kind": "search", "space": {"offset": 0}}})
    }

    fn resources() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("bigram".to_owned(), "{\"n\":2}".to_owned()),
            ("trigram".to_owned(), "{\"n\":3}".to_owned()),
        ])
    }

    fn identity(request: &serde_json::Value, resources: &BTreeMap<String, String>) -> String {
        checkpoint_identity(&request.to_string(), resources)
            .unwrap()
            .to_string()
    }

    #[test]
    fn identity_hashes_the_specified_byte_sequence() {
        let canonical = request().to_string();
        let catalog = crate::definition::bundled_catalog_json("enigma-i").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"enigma-checkpoint-identity/1\n");
        expected.extend_from_slice(canonical.as_bytes());
        expected.push(b'\n');
        expected.extend_from_slice(catalog.as_bytes());
        expected.push(b'\n');
        expected.extend_from_slice(b"bigram\n7\n{\"n\":2}trigram\n7\n{\"n\":3}");
        assert_eq!(identity(&request(), &resources()), sha256(&expected));
        assert_eq!(identity(&request(), &resources()).len(), 64);
    }

    #[test]
    fn identity_ignores_formatting_and_key_order() {
        let compact = identity(&request(), &resources());
        let reordered = r#" { "text" : "ABCDEF", "job": {"space": {"offset": 0}, "kind": "search"},
            "machine": {"definition": {"id": "enigma-i", "kind": "bundled"}},
            "protocol_version": 1 } "#;
        let reformatted = checkpoint_identity(reordered, &resources()).unwrap();
        assert_eq!(reformatted.to_string(), compact);
    }

    #[test]
    fn identity_changes_with_every_bound_input() {
        let base = identity(&request(), &resources());
        let mut changed = Vec::new();
        for (pointer, value) in [
            ("/job/space/offset", json!(128)),
            ("/text", json!("ABCDEG")),
            ("/machine/definition/id", json!("enigma-m3")),
            ("/protocol_version", json!(2)),
        ] {
            let mut variant = request();
            *variant.pointer_mut(pointer).unwrap() = value;
            changed.push(identity(&variant, &resources()));
        }
        let mut passes = request();
        passes["job"]["passes"] = json!([{"kind": "hill_climb"}]);
        changed.push(identity(&passes, &resources()));
        let mut byte = resources();
        byte.insert("bigram".to_owned(), "{\"n\":3}".to_owned());
        changed.push(identity(&request(), &byte));
        let mut renamed = resources();
        let content = renamed.remove("trigram").unwrap();
        renamed.insert("trigrams".to_owned(), content);
        changed.push(identity(&request(), &renamed));
        let mut fewer = resources();
        fewer.remove("trigram");
        changed.push(identity(&request(), &fewer));
        for (index, digest) in changed.iter().enumerate() {
            assert_ne!(digest, &base, "variant {index}");
        }
    }

    #[test]
    fn identity_binds_custom_definitions_through_the_request_only() {
        let mut custom = request();
        custom["machine"]["definition"] = json!({"kind": "custom", "value": {"wheels": []}});
        let digest = identity(&custom, &resources());
        let mut expected = Vec::new();
        expected.extend_from_slice(b"enigma-checkpoint-identity/1\n");
        expected.extend_from_slice(custom.to_string().as_bytes());
        expected.push(b'\n');
        expected.extend_from_slice(b"bigram\n7\n{\"n\":2}trigram\n7\n{\"n\":3}");
        assert_eq!(digest, sha256(&expected));
    }

    #[test]
    fn identity_rejects_non_strict_json_and_unknown_catalog_entries() {
        assert_eq!(
            checkpoint_identity(r#"{"a":1,"a":2}"#, &resources()),
            Err(CheckpointIdentityError::InvalidRequest)
        );
        assert_eq!(
            checkpoint_identity(r#"{"a":1} x"#, &resources()),
            Err(CheckpointIdentityError::InvalidRequest)
        );
        let mut unknown = request();
        unknown["machine"]["definition"]["id"] = json!("enigma-z");
        assert_eq!(
            checkpoint_identity(&unknown.to_string(), &resources()),
            Err(CheckpointIdentityError::UnknownBundledDefinition(
                "enigma-z".to_owned()
            ))
        );
    }
}
