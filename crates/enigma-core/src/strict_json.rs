//! Duplicate-key-strict JSON parsing shared by the definition and request layers.
//!
//! [`StrictValue`] mirrors `serde_json::Value` but rejects duplicate object keys during
//! deserialization, which `serde_json::Value` silently accepts (last write wins). Both
//! the key-free definition validator and the request parser need that guarantee before
//! they can apply exact-field rules, so the visitor lives here instead of being
//! duplicated per module.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::fmt;

/// A parsed JSON value that never contained a duplicate object key.
pub(crate) enum StrictValue {
    /// A scalar (`null`, boolean, number, or string).
    Value(Value),
    /// A JSON array, in source order.
    Array(Vec<StrictValue>),
    /// A JSON object, stored sorted so lookups and emission are deterministic.
    Object(BTreeMap<String, StrictValue>),
}

impl StrictValue {
    /// Converts into the equivalent `serde_json::Value`, collapsing nested strictness.
    pub(crate) fn into_value(self) -> Value {
        match self {
            Self::Value(value) => value,
            Self::Array(values) => Value::Array(values.into_iter().map(Self::into_value).collect()),
            Self::Object(values) => Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, value.into_value()))
                    .collect(),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::Number(Number::from(value))))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::Number(Number::from(value))))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue::Value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::String(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::String(value)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Value(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate object field {key:?}"
                        )));
                    }
                    values.insert(key, value);
                }
                Ok(StrictValue::Object(values))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
