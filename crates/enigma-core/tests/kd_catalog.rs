use enigma_core::{
    DefinitionSource, Direction, Movement, SlotConfiguration, TransformConfiguration,
};
use serde_json::json;

#[test]
fn kd_structure_turnovers_and_double_step() {
    let definition = DefinitionSource::parse_value(json!({"kind":"bundled","id":"enigma-kd"}))
        .unwrap()
        .resolve()
        .unwrap();
    assert_eq!(definition.slots().len(), 5);
    assert_eq!(definition.slots()[0].wheel(), Some("D"));
    assert_eq!(definition.slots()[0].movement(), Movement::Fixed);
    assert_eq!(definition.slots()[4].wheel(), Some("ETW"));
    assert_eq!(definition.slots()[4].movement(), Movement::Fixed);
    assert_eq!(
        definition.rewirable_fixed_pairs("D"),
        Some(&[('B', 'O')][..])
    );
    for wheel in &definition.wheels()[..3] {
        for c in 'A'..='Z' {
            assert_eq!(wheel.at_turnover(c), "SUYAEHLNQ".contains(c));
        }
    }
    let pairs = [
        "AK", "CT", "DV", "EP", "FN", "GL", "HM", "IJ", "QW", "RY", "SX", "UZ",
    ]
    .map(|p| {
        let mut c = p.chars();
        (c.next().unwrap(), c.next().unwrap())
    });
    let configuration = TransformConfiguration::new(
        vec![
            SlotConfiguration::new("reflector", "D", 'A', 'A').with_pairs(pairs.to_vec()),
            SlotConfiguration::new("left", "III", 'K', 'F'),
            SlotConfiguration::new("middle", "II", 'R', 'C'),
            SlotConfiguration::new("right", "I", 'S', 'P'),
            SlotConfiguration::new("etw", "ETW", 'A', 'A'),
        ],
        vec![],
    );
    let mut engine = configuration
        .resolve(&definition)
        .unwrap()
        .into_engine()
        .unwrap();
    // Right S triggers middle R->S; middle S then triggers its second step.
    for expected in ["AKSTA", "ALTUA", "ALUVA"] {
        engine.transform("A", Direction::Encrypt).unwrap();
        assert_eq!(engine.positions().iter().collect::<String>(), expected);
    }
}
