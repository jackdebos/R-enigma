//! Structural scoring selections; paths are metadata, never loaded by the core.
use crate::space::SearchDiagnostic;
use serde_json::Value;
use std::collections::HashSet;

/// Exact protocol measure identifier (no aliases).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MeasureId {
    /// Alphabet-scaled coincidence.
    Ic,
    /// Positive Shannon entropy.
    Entropy,
    /// Order-one Sinkov score.
    SinkovMonogram,
    /// Order-two Sinkov score.
    SinkovBigram,
    /// Order-three Sinkov score.
    SinkovTrigram,
    /// Order-four Sinkov score.
    SinkovQuadgram,
    /// Order-five Sinkov score.
    SinkovPentagram,
    /// Order-six Sinkov score.
    SinkovHexagram,
    /// Weighted overlapping dictionary score.
    Trie,
}

impl MeasureId {
    /// Stable wire spelling.
    pub fn id(self) -> &'static str {
        match self {
            Self::Ic => "ic",
            Self::Entropy => "entropy",
            Self::SinkovMonogram => "sinkov_monogram",
            Self::SinkovBigram => "sinkov_bigram",
            Self::SinkovTrigram => "sinkov_trigram",
            Self::SinkovQuadgram => "sinkov_quadgram",
            Self::SinkovPentagram => "sinkov_pentagram",
            Self::SinkovHexagram => "sinkov_hexagram",
            Self::Trie => "trie",
        }
    }

    /// Required n-gram order, or `None` for non-Sinkov measures.
    pub fn order(self) -> Option<usize> {
        match self {
            Self::SinkovMonogram => Some(1),
            Self::SinkovBigram => Some(2),
            Self::SinkovTrigram => Some(3),
            Self::SinkovQuadgram => Some(4),
            Self::SinkovPentagram => Some(5),
            Self::SinkovHexagram => Some(6),
            _ => None,
        }
    }

    /// Minimum number of Unicode scalars before scoring.
    pub fn minimum_samples(self) -> usize {
        if self == Self::Ic {
            2
        } else {
            self.order().unwrap_or(1)
        }
    }

    /// Whether supplied resource content is required.
    pub fn requires_resource(self) -> bool {
        self.order().is_some() || self == Self::Trie
    }
}

/// Validated external path reference associated with one selected measure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceReference {
    measure: MeasureId,
    path: String,
}

impl ResourceReference {
    /// Selected measure owning the reference.
    pub fn measure(&self) -> MeasureId {
        self.measure
    }
    /// Exact path spelling; no normalization or expansion is performed.
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn error(
    code: &'static str,
    message: impl Into<String>,
    path: impl Into<String>,
) -> Vec<SearchDiagnostic> {
    vec![SearchDiagnostic::new(code, message, path)]
}

pub(crate) fn parse_measures(ids: &[String]) -> Result<Vec<MeasureId>, Vec<SearchDiagnostic>> {
    const ALL: [MeasureId; 9] = [
        MeasureId::Ic,
        MeasureId::Entropy,
        MeasureId::SinkovMonogram,
        MeasureId::SinkovBigram,
        MeasureId::SinkovTrigram,
        MeasureId::SinkovQuadgram,
        MeasureId::SinkovPentagram,
        MeasureId::SinkovHexagram,
        MeasureId::Trie,
    ];
    ids.iter()
        .enumerate()
        .map(|(i, id)| {
            ALL.into_iter()
                .find(|measure| measure.id() == id)
                .ok_or_else(|| {
                    error(
                        "unsupported_measure",
                        format!("unknown measure {id:?}; use an exact supported ID"),
                        format!("/job/measures/{i}"),
                    )
                })
        })
        .collect()
}

pub(crate) fn parse_references(
    measures: &[MeasureId],
    value: Option<&Value>,
) -> Result<Vec<ResourceReference>, Vec<SearchDiagnostic>> {
    let mut references = Vec::new();
    let mut seen = HashSet::new();
    if let Some(value) = value {
        let object = value.as_object().ok_or_else(|| {
            error(
                "unsupported_resource",
                "resources must be an object of external path references",
                "/job/resources",
            )
        })?;
        for (id, reference) in object {
            let escaped = id.replace('~', "~0").replace('/', "~1");
            let base = format!("/job/resources/{escaped}");
            let path_location = format!("{base}/path");
            let measure = measures
                .iter()
                .copied()
                .find(|measure| measure.id() == id && measure.requires_resource())
                .ok_or_else(|| {
                    error(
                        "unsupported_resource",
                        "reference must belong to a selected resource-dependent measure",
                        &path_location,
                    )
                })?;
            let reference = reference.as_object().ok_or_else(|| {
                error(
                    "unsupported_resource",
                    "reference must contain exactly a nonempty string path",
                    &path_location,
                )
            })?;
            if let Some(key) = reference.keys().find(|key| key.as_str() != "path") {
                return Err(error(
                    "unknown_field",
                    format!("unknown reference field {key:?}; inline content is not supported"),
                    format!("{base}/{}", key.replace('~', "~0").replace('/', "~1")),
                ));
            }
            let path = reference
                .get("path")
                .and_then(Value::as_str)
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    error(
                        "unsupported_resource",
                        "provide a nonempty string path",
                        &path_location,
                    )
                })?;
            references.push(ResourceReference {
                measure,
                path: path.to_owned(),
            });
            seen.insert(measure);
        }
    }
    for measure in measures {
        if measure.requires_resource() && !seen.contains(measure) {
            return Err(error(
                "unsupported_resource",
                format!("provide an external path for {}", measure.id()),
                format!("/job/resources/{}/path", measure.id()),
            ));
        }
    }
    Ok(references)
}
