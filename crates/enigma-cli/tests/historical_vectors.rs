//! Historical known-answer vectors driven end-to-end through the CLI.
//!
//! Source: Frode Weierud's CryptoCellar, *German Army Enigma Keys for July 1941, Batch B*,
//! <https://cryptocellar.org/bgac/e-keys-july-1941.html> (updated 27 September 2026), part
//! of *Breaking German Army Ciphers* by Geoff Sullivan and Frode Weierud. The page supplies
//! each recovered daily key (UKW, wheel order, Stecker and Rings) and, per message, the two
//! trigrams of the indicator plus the recovered `Start` message key.
//!
//! Each vector reproduces the documented operator procedure on a known key: set the wheels to
//! the first indicator trigram (`Grundstellung`) and decipher the second trigram to recover
//! the `Start` message key; the reciprocal encipherment must reproduce the second trigram.
//! Only the sourced values are used here. The historical wiring itself comes from the
//! bundled `enigma-i` catalog (`docs/historical-catalog.md`); no wiring or vector value is
//! invented in this file. The explanatory `AIK SUD -> WER` example for 5 July 1941 is stated
//! in the source page's own prose.
//!
//! The 8 July 1941 Nr. 122 row is deliberately omitted: the source table overflows that row
//! (three trigrams in the `Indicator` column, verified to disagree with the engine), so the
//! clean Nr. 127 row of the same day is used instead.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

/// One sourced indicator vector: a daily key plus one message's indicator and message key.
struct Vector {
    date: &'static str,
    message: &'static str,
    /// Wheel order left-to-right: left, middle, right.
    rotors: [&'static str; 3],
    /// Ringstellung left-to-right: left, middle, right.
    rings: [&'static str; 3],
    /// Stecker pairs, each a two-letter string.
    stecker: &'static [&'static str],
    /// First indicator trigram: the `Grundstellung` window position.
    ground: &'static str,
    /// Second indicator trigram: the enciphered message key.
    indicator: &'static str,
    /// Recovered message key (the `Start` column).
    start: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        date: "1941-07-05",
        message: "Nr. 101 (DEROP)",
        rotors: ["III", "V", "IV"],
        rings: ["W", "H", "J"],
        stecker: &["BI", "CW", "EQ", "FX", "HZ", "JN", "KY", "MT", "OV", "PR"],
        ground: "AIK",
        indicator: "SUD",
        start: "WER",
    },
    Vector {
        date: "1941-07-06",
        message: "Nr. 107 (ABGUX)",
        rotors: ["V", "I", "III"],
        rings: ["I", "R", "D"],
        stecker: &["AN", "BM", "DH", "EI", "KQ", "LS", "OT", "PV", "RU", "YZ"],
        ground: "FVT",
        indicator: "MML",
        start: "UHF",
    },
    Vector {
        date: "1941-07-06",
        message: "Nr. 108 (ABAHP)",
        rotors: ["V", "I", "III"],
        rings: ["I", "R", "D"],
        stecker: &["AN", "BM", "DH", "EI", "KQ", "LS", "OT", "PV", "RU", "YZ"],
        ground: "RFV",
        indicator: "ACK",
        start: "MKO",
    },
    Vector {
        date: "1941-07-07",
        message: "Nr. 113 (XIVFG)",
        rotors: ["II", "IV", "V"],
        rings: ["B", "U", "L"],
        stecker: &["AV", "BS", "CG", "DL", "FU", "HZ", "IN", "KM", "OW", "RX"],
        ground: "LMN",
        indicator: "JGO",
        start: "OPQ",
    },
    Vector {
        date: "1941-07-08",
        message: "Nr. 127 (HBNVE)",
        rotors: ["IV", "III", "II"],
        rings: ["P", "K", "F"],
        stecker: &["CY", "EL", "FH", "GS", "IJ", "KQ", "MW", "PV", "RZ", "TU"],
        ground: "DRU",
        indicator: "QBP",
        start: "TRE",
    },
    Vector {
        date: "1941-07-09",
        message: "Nr. 139 (BEYWU)",
        rotors: ["III", "I", "V"],
        rings: ["N", "A", "V"],
        stecker: &["AC", "BN", "FM", "GI", "JL", "KO", "PU", "QX", "RZ", "TV"],
        ground: "MIN",
        indicator: "MER",
        start: "ALA",
    },
    Vector {
        date: "1941-07-11",
        message: "Nr. 187 (AWTZK)",
        rotors: ["I", "IV", "III"],
        rings: ["E", "X", "S"],
        stecker: &["AO", "BF", "CQ", "DH", "EW", "GJ", "KX", "NU", "PY", "RT"],
        ground: "DUJ",
        indicator: "GEH",
        start: "ERT",
    },
    Vector {
        date: "1941-07-12",
        message: "Nr. 194 (MAKJH)",
        rotors: ["II", "V", "IV"],
        rings: ["Y", "C", "M"],
        stecker: &["AJ", "BD", "CZ", "EH", "GU", "IK", "LV", "MQ", "NX", "OS"],
        ground: "FZK",
        indicator: "EWR",
        start: "RHL",
    },
    Vector {
        date: "1941-07-13",
        message: "Nr. 199 (MYFRE)",
        rotors: ["IV", "II", "III"],
        rings: ["G", "T", "O"],
        stecker: &["AD", "EH", "GY", "IM", "KN", "LR", "OZ", "QV", "TX", "WU"],
        ground: "XIC",
        indicator: "YUU",
        start: "TGB",
    },
    Vector {
        date: "1941-07-14",
        message: "Nr. 203 (CFYZR)",
        rotors: ["V", "III", "I"],
        rings: ["L", "W", "B"],
        stecker: &["BT", "CH", "DR", "EW", "FU", "GK", "JO", "LV", "MS", "PZ"],
        ground: "ULR",
        indicator: "AME",
        start: "BER",
    },
];

fn request(vector: &Vector, text: &str, direction: &str) -> Value {
    let slots: Vec<Value> = vector
        .ground
        .chars()
        .enumerate()
        .map(|(index, position)| {
            let id = ["left", "middle", "right"][index];
            json!({
                "id": id,
                "wheel": vector.rotors[index],
                "position": position.to_string(),
                "ring": vector.rings[index],
            })
        })
        .collect();

    let plugboard: Vec<Value> = vector
        .stecker
        .iter()
        .map(|pair| json!([pair[0..1].to_string(), pair[1..2].to_string()]))
        .collect();

    let mut configuration_slots = vec![json!({
        "id": "reflector",
        "wheel": "B",
        "position": "A",
        "ring": "A",
    })];
    configuration_slots.extend(slots);

    json!({
        "protocol_version": 1,
        "machine": {"definition": {"kind": "bundled", "id": "enigma-i"}},
        "job": {
            "kind": "transform",
            "configuration": {
                "slots": configuration_slots,
                "plugboard": plugboard
            },
            "text": text,
            "direction": direction
        }
    })
}

fn run(request: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enigma"))
        .args(["--request", "-"])
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
fn historical_indicators_decipher_to_the_message_key() {
    for vector in VECTORS {
        let decipher = request(vector, vector.indicator, "decrypt");
        let recovered = transform(&decipher);
        assert_eq!(
            recovered,
            vector.start,
            "{} {}: decrypting indicator {} under the {}/{}/{} key did not recover {}",
            vector.date,
            vector.message,
            vector.indicator,
            vector.rotors[0],
            vector.rotors[1],
            vector.rotors[2],
            vector.start
        );
    }
}

#[test]
fn historical_message_keys_encipher_back_to_the_indicator() {
    for vector in VECTORS {
        let encipher = request(vector, vector.start, "encrypt");
        let indicator = transform(&encipher);
        assert_eq!(
            indicator,
            vector.indicator,
            "{} {}: enciphering message key {} under the {}/{}/{} key did not reproduce {}",
            vector.date,
            vector.message,
            vector.start,
            vector.rotors[0],
            vector.rotors[1],
            vector.rotors[2],
            vector.indicator
        );
    }
}

/// Guards the vector table itself: ten distinct messages, each with a complete key.
#[test]
fn vector_table_is_well_formed() {
    assert_eq!(VECTORS.len(), 10);
    for vector in VECTORS {
        assert_eq!(vector.ground.chars().count(), 3, "{} ground", vector.date);
        assert_eq!(
            vector.indicator.chars().count(),
            3,
            "{} indicator",
            vector.date
        );
        assert_eq!(vector.start.chars().count(), 3, "{} start", vector.date);
        assert_eq!(vector.stecker.len(), 10, "{} stecker", vector.date);
        assert!(
            vector.ground.chars().all(|c| c.is_ascii_uppercase()),
            "{} ground must be uppercase",
            vector.date
        );
    }
}
