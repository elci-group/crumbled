//! Explicit, identity-scoped policy approval. Names alone never grant permission.
use crumbled_core::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub cookie: CookieIdentity,
    pub category: PermissionClass,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    #[serde(default = "default_decisions")]
    pub decisions: BTreeMap<PermissionClass, Decision>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}
pub fn default_decisions() -> BTreeMap<PermissionClass, Decision> {
    [
        (PermissionClass::Necessary, Decision::Allow),
        (PermissionClass::Preferences, Decision::Gate),
        (PermissionClass::Analytics, Decision::Gate),
        (PermissionClass::Marketing, Decision::Gate),
        (PermissionClass::Unknown, Decision::Block),
    ]
    .into()
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            decisions: default_decisions(),
            rules: vec![],
        }
    }
}
impl Policy {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let policy: Self =
            serde_json::from_str(text).map_err(|e| format!("invalid policy: {e}"))?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported policy schema_version".into());
        }
        if self.decisions.len() != 5 {
            return Err("policy decisions must specify all five permission classes".into());
        }
        if self.decisions.get(&PermissionClass::Unknown) != Some(&Decision::Block) {
            return Err("unknown behaviour must remain blocked".into());
        }
        for (class, decision) in &self.decisions {
            if *class != PermissionClass::Necessary && *decision == Decision::Allow {
                return Err("consent classes cannot use an unconditional allow decision".into());
            }
        }
        let mut identities = BTreeSet::new();
        for rule in &self.rules {
            if rule.reason.trim().is_empty() {
                return Err("policy rule requires an approval reason".into());
            }
            if rule
                .cookie
                .name
                .as_ref()
                .is_none_or(|name| name.trim().is_empty())
            {
                return Err("unresolved cookie names cannot be approved".into());
            }
            if rule.cookie.application.trim().is_empty() || rule.cookie.origin.trim().is_empty() {
                return Err("policy identity requires application and origin".into());
            }
            if !identities.insert(rule.cookie.id()) {
                return Err("duplicate policy identity; rules must not conflict".into());
            }
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<String, String> {
        self.validate()?;
        // Rule order does not affect the meaning of the policy.
        let mut canonical = self.clone();
        canonical.rules.sort_by_key(|rule| rule.cookie.id());
        serde_json::to_vec(&canonical)
            .map(|bytes| sha256(&bytes))
            .map_err(|e| e.to_string())
    }
    pub fn assess(&self, finding: Finding, timestamp: Option<u64>) -> Result<Assessment, String> {
        let digest = self.fingerprint()?;
        let rule = self.rules.iter().find(|rule| rule.cookie == finding.cookie);
        Ok(self.assess_with_rule(finding, rule, &digest, timestamp))
    }
    /// Resolve policy once per batch, not once per behaviour.
    pub fn assess_all(
        &self,
        findings: Vec<Finding>,
        timestamp: Option<u64>,
    ) -> Result<Vec<Assessment>, String> {
        let digest = self.fingerprint()?;
        let rules: BTreeMap<_, _> = self
            .rules
            .iter()
            .map(|rule| (rule.cookie.id(), rule))
            .collect();
        Ok(findings
            .into_iter()
            .map(|finding| {
                let rule = rules.get(&finding.cookie.id()).copied();
                self.assess_with_rule(finding, rule, &digest, timestamp)
            })
            .collect())
    }
    fn assess_with_rule(
        &self,
        finding: Finding,
        rule: Option<&PolicyRule>,
        digest: &str,
        timestamp: Option<u64>,
    ) -> Assessment {
        let mut finding = DeterministicClassifier.classify(&finding);
        let reason;
        if let Some(rule) = rule {
            reason = rule.reason.clone();
            finding.classification = Classification {
                value: rule.category,
                confidence: Confidence::Confirmed,
                method: Method::UserPolicy,
                evidence: vec![Evidence {
                    source: "user-policy".into(),
                    method: Method::UserPolicy,
                    confidence: Confidence::Confirmed,
                    location: None,
                    timestamp,
                    content_sha256: digest.into(),
                    detail: reason.clone(),
                }],
            };
        } else {
            reason = "No reviewed policy rule matches the full cookie identity".into();
        }
        let decision = self
            .decisions
            .get(&finding.classification.value)
            .copied()
            .unwrap_or(Decision::Block);
        Assessment {
            finding,
            decision,
            reason,
            gated: false,
        }
    }
}
#[derive(Default)]
pub struct DeterministicClassifier;
impl Classifier for DeterministicClassifier {
    fn classify(&self, finding: &Finding) -> Finding {
        let mut result = finding.clone();
        result.classification = Classification {
            value: PermissionClass::Unknown,
            confidence: Confidence::Unknown,
            method: Method::StaticRule,
            evidence: finding
                .evidence
                .iter()
                .map(|e| Evidence {
                    detail: "Cookie purpose is not established by its name or lexical API access"
                        .into(),
                    ..e.clone()
                })
                .collect(),
        };
        result
    }
}
#[derive(Default)]
pub struct DefaultPolicy;
impl PolicyEngine for DefaultPolicy {
    fn evaluate(&self, finding: &Finding) -> Decision {
        if finding.classification.confidence != Confidence::Confirmed
            || finding.classification.method != Method::UserPolicy
            || finding.classification.evidence.is_empty()
        {
            return Decision::Block;
        }
        default_decisions()
            .get(&finding.classification.value)
            .copied()
            .unwrap_or(Decision::Block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsafe_configuration_is_rejected() {
        let mut p = Policy::default();
        p.decisions
            .insert(PermissionClass::Unknown, Decision::Allow);
        assert!(p.validate().is_err());
        let mut p = Policy::default();
        p.decisions
            .insert(PermissionClass::Analytics, Decision::Allow);
        assert!(p.validate().is_err());
        assert!(Policy::from_json(r#"{"schema_version":1,"rulez":[]}"#).is_err());
    }
    #[test]
    fn all_valid_unknown_decisions_are_block() {
        for decision in [Decision::Allow, Decision::Gate, Decision::Block] {
            let mut p = Policy::default();
            p.decisions.insert(PermissionClass::Unknown, decision);
            assert_eq!(p.validate().is_ok(), decision == Decision::Block);
        }
    }
}
