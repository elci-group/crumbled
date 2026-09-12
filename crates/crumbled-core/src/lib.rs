//! Canonical contracts, independent of detectors, frameworks and integrations.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const SCHEMA_VERSION: u32 = 1;
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// Length prefixes prevent ambiguity between adjacent identity components.
pub fn identity_hash(parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: String,
    pub method: Method,
    pub confidence: Confidence,
    pub location: Option<Location>,
    /// Source modification time, not a claim of runtime observation.
    pub timestamp: Option<u64>,
    pub content_sha256: String,
    /// Rule explanation. Cookie values and entire source lines are omitted.
    pub detail: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    StaticRule,
    RuntimeObservation,
    DependencyKnowledge,
    Configuration,
    UserPolicy,
    Manual,
    LlmAssisted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub byte_offset: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Probable,
    Possible,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Read,
    Modify,
    Delete,
    Send,
    Receive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionClass {
    Necessary,
    Preferences,
    Analytics,
    Marketing,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Gate,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CookieIdentity {
    /// None is unresolved, never a wildcard policy selector.
    pub name: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub origin: String,
    pub application: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}
impl CookieIdentity {
    pub fn id(&self) -> String {
        let fields = [
            self.name.as_deref(),
            self.domain.as_deref(),
            self.path.as_deref(),
        ];
        let mut parts = vec![self.application.as_str(), self.origin.as_str()];
        for field in fields {
            parts.push(if field.is_some() { "known" } else { "unknown" });
            parts.push(field.unwrap_or(""));
        }
        for (key, value) in &self.attributes {
            parts.push(key);
            parts.push(value);
        }
        format!("cookie:{}", identity_hash(&parts))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub value: PermissionClass,
    pub confidence: Confidence,
    pub method: Method,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub cookie: CookieIdentity,
    pub operation: Operation,
    pub technical_classification: String,
    pub classification: Classification,
    pub confidence: Confidence,
    pub declared: bool,
    pub observed: bool,
    pub correlated: bool,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub finding: Finding,
    pub decision: Decision,
    pub reason: String,
    pub gated: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub label: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub relation: String,
    pub to: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CookieGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}
impl CookieGraph {
    pub fn from_assessments(items: &[Assessment]) -> Self {
        let mut nodes = BTreeMap::<String, Node>::new();
        let mut edges = Vec::new();
        let mut add = |id: String, kind: &str, label: String| {
            nodes.insert(
                id.clone(),
                Node {
                    id: id.clone(),
                    kind: kind.into(),
                    label,
                },
            );
            id
        };
        for assessment in items {
            let f = &assessment.finding;
            let app = add(
                format!("application:{}", identity_hash(&[&f.cookie.application])),
                "Application",
                f.cookie.application.clone(),
            );
            let cookie = add(
                f.cookie.id(),
                "Cookie",
                f.cookie.name.clone().unwrap_or_else(|| "unresolved".into()),
            );
            let operation = add(
                f.id.clone(),
                "StorageOperation",
                format!("{:?}", f.operation),
            );
            let permission = add(
                format!("permission:{:?}", f.classification.value),
                "Permission",
                format!("{:?}", f.classification.value),
            );
            edges.push(Edge {
                from: cookie.clone(),
                relation: "requires".into(),
                to: permission,
            });
            edges.push(Edge {
                from: operation.clone(),
                relation: match f.operation {
                    Operation::Create => "creates",
                    Operation::Read => "reads",
                    Operation::Modify => "modifies",
                    Operation::Delete => "deletes",
                    Operation::Send => "sends",
                    Operation::Receive => "receives",
                }
                .into(),
                to: cookie.clone(),
            });
            if let Some(domain) = &f.cookie.domain {
                let id = add(
                    format!("domain:{}", identity_hash(&[domain])),
                    "Domain",
                    domain.clone(),
                );
                edges.push(Edge {
                    from: cookie,
                    relation: "belongs_to".into(),
                    to: id,
                });
            }
            for (index, ev) in f
                .evidence
                .iter()
                .chain(&f.classification.evidence)
                .enumerate()
            {
                let id = add(
                    format!("evidence:{}:{index}", f.id),
                    "Evidence",
                    ev.detail.clone(),
                );
                edges.push(Edge {
                    from: operation.clone(),
                    relation: "supported_by".into(),
                    to: id,
                });
                if let Some(loc) = &ev.location {
                    let label = loc.path.to_string_lossy().into_owned();
                    let module = add(
                        format!("module:{}", identity_hash(&[&f.cookie.application, &label])),
                        "Module",
                        label,
                    );
                    edges.push(Edge {
                        from: app.clone(),
                        relation: "contains".into(),
                        to: module.clone(),
                    });
                    edges.push(Edge {
                        from: module,
                        relation: "contains".into(),
                        to: operation.clone(),
                    });
                }
            }
        }
        edges.sort();
        edges.dedup();
        Self {
            nodes: nodes.into_values().collect(),
            edges,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub finding_id: Option<String>,
    pub location: Option<Location>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub command: String,
    pub application: String,
    pub analysis_scope: String,
    pub assessments: Vec<Assessment>,
    pub graph: CookieGraph,
    pub diagnostics: Vec<Diagnostic>,
    pub exit_code: u8,
    pub artifact: Option<serde_json::Value>,
}
impl Report {
    pub fn new(command: &str, application: &str, assessments: Vec<Assessment>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            application: application.into(),
            analysis_scope:
                "lexical static analysis only; no runtime observation or enforcement attestation"
                    .into(),
            graph: CookieGraph::from_assessments(&assessments),
            assessments,
            diagnostics: vec![],
            exit_code: 0,
            artifact: None,
        }
    }
    pub fn diagnostic(&mut self, code: &str, message: impl Into<String>, exit_code: u8) {
        self.diagnostics.push(Diagnostic {
            code: code.into(),
            message: message.into(),
            finding_id: None,
            location: None,
        });
        self.exit_code = exit_code;
    }
}
pub trait Detector {
    fn detect(&self, source: &Path) -> Result<Vec<Finding>, String>;
}
pub trait Classifier {
    fn classify(&self, finding: &Finding) -> Finding;
}
pub trait PolicyEngine {
    fn evaluate(&self, finding: &Finding) -> Decision;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_not_just_a_name() {
        let base = CookieIdentity {
            name: Some("session".into()),
            domain: Some("a.test".into()),
            path: Some("/".into()),
            origin: "https://a.test".into(),
            application: "store".into(),
            attributes: BTreeMap::new(),
        };
        for index in 0..6 {
            let mut changed = base.clone();
            match index {
                0 => changed.domain = Some("b.test".into()),
                1 => changed.path = Some("/checkout".into()),
                2 => changed.origin = "https://b.test".into(),
                3 => changed.application = "another".into(),
                4 => {
                    changed.attributes.insert("secure".into(), "true".into());
                }
                _ => changed.name = None,
            }
            assert_ne!(base.id(), changed.id());
        }
        assert_ne!(identity_hash(&["ab", "c"]), identity_hash(&["a", "bc"]));
    }
}
