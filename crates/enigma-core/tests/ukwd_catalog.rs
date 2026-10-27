use enigma_core::{DefinitionSource, SlotConfiguration, TransformConfiguration};
use serde_json::{json, Value};

#[test]
fn ukwd_catalogs_preserve_the_original_rotors_and_stepping() {
    for (id, original, ukwd) in [
        (
            "enigma-i-ukwd",
            include_str!("../catalog/enigma-i.json"),
            include_str!("../catalog/enigma-i-ukwd.json"),
        ),
        (
            "enigma-m3-ukwd",
            include_str!("../catalog/enigma-m3.json"),
            include_str!("../catalog/enigma-m3-ukwd.json"),
        ),
    ] {
        let original: Value = serde_json::from_str(original).unwrap();
        let ukwd: Value = serde_json::from_str(ukwd).unwrap();
        assert_eq!(original["alphabet"], ukwd["alphabet"]);
        assert_eq!(original["stepping"], ukwd["stepping"]);
        assert_eq!(original["slots"][1], ukwd["slots"][1]);
        assert_eq!(original["slots"][2], ukwd["slots"][2]);
        assert_eq!(original["slots"][3], ukwd["slots"][3]);
        let originals = original["wheels"].as_array().unwrap();
        let wheels = ukwd["wheels"].as_array().unwrap();
        assert_eq!(
            &originals[..originals.len() - 2],
            &wheels[..wheels.len() - 1]
        );
        assert_eq!(
            wheels.last().unwrap(),
            &json!({
                "name":"D", "rewirable":{"fixed_pairs":[["B","O"]]}, "turnovers":[]
            })
        );
        let bundle = DefinitionSource::parse_value(json!({"kind":"bundled","id":id}))
            .unwrap()
            .resolve()
            .unwrap();
        let custom = DefinitionSource::parse_value(json!({"kind":"custom","value":ukwd}))
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(bundle, custom);
        assert_eq!(bundle.rewirable_fixed_pairs("D"), Some(&[('B', 'O')][..]));
    }
}

#[test]
fn typed_pairs_apply_position_ring_and_preserve_turnovers() {
    let definition = DefinitionSource::parse_value(json!({"kind":"custom","value":{
        "alphabet":["A","B","C","D"],
        "wheels":[
            {"name":"D","rewirable":{"fixed_pairs":[]},"turnovers":["C"]},
            {"name":"R","wiring":["A","B","C","D"],"turnovers":[]}],
        "slots":[
            {"id":"ukw","role":"reflector","movement":"fixed","wheel":"D"},
            {"id":"rotor","role":"rotor","movement":"fixed","wheel":"R"}],
        "stepping":{"rules":[]}
    }}))
    .unwrap()
    .resolve()
    .unwrap();
    let entry =
        SlotConfiguration::new("ukw", "D", 'C', 'B').with_pairs(vec![('A', 'B'), ('C', 'D')]);
    assert_eq!(entry.pairs(), Some(&[('A', 'B'), ('C', 'D')][..]));
    let configuration = TransformConfiguration::new(
        vec![entry, SlotConfiguration::new("rotor", "R", 'A', 'A')],
        vec![],
    );
    let resolved = configuration.resolve(&definition).unwrap();
    let wheel = &resolved.topology().wheels()[0];
    assert!(wheel.at_turnover('C'));
    assert!(!wheel.at_turnover('B'));
    assert_eq!(wheel.forward('A', 'C', 'B'), Some('D'));
    let mut engine = resolved.into_engine().unwrap();
    assert_eq!(
        engine
            .transform("ABCD", enigma_core::Direction::Encrypt)
            .unwrap(),
        "DCBA"
    );
}
