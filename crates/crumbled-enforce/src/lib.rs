//! Plans, reviewed topology locks, and integrity verification.
//! This crate does not claim that generating a plan controls an execution path.
use crumbled_core::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionGate {
    pub id: String,
    pub category: PermissionClass,
    pub resources: Vec<String>,
    pub default_state: String,
    pub activation_condition: String,
    pub compiled: bool,
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub schema_version: u32,
    pub gates: Vec<PermissionGate>,
    pub applicable: bool,
    pub changes: Vec<String>,
}
pub fn compile(items: &[Assessment]) -> EnforcementPlan {
    let gates = items.iter().filter(|a| a.decision != Decision::Allow).map(|a| PermissionGate {
        id: format!("gate:{}", identity_hash(&[&a.finding.id])), category: a.finding.classification.value,
        resources: vec![a.finding.id.clone()], default_state: "blocked".into(),
        activation_condition: if a.decision == Decision::Gate { "explicit consent for this category".into() } else { "never; policy blocks this resource".into() },
        compiled: false, reason: "No execution-path compiler is installed; lexical evidence cannot establish complete enforcement".into(),
    }).collect();
    // Even an empty lexical scan does not prove that an application has no dynamic behaviour.
    EnforcementPlan {
        schema_version: SCHEMA_VERSION,
        gates,
        applicable: false,
        changes: vec![],
    }
}
pub fn violations(items: &[Assessment]) -> Vec<Diagnostic> {
    items
        .iter()
        .filter(|a| a.decision != Decision::Allow)
        .map(|a| Diagnostic {
            code: if a.decision == Decision::Block {
                "CRUMBLED_BLOCKED_BEHAVIOUR"
            } else {
                "CRUMBLED_UNCONTROLLED_PATH"
            }
            .into(),
            message: format!(
                "{}: {:?}; no verified enforcement path",
                a.finding
                    .cookie
                    .name
                    .as_deref()
                    .unwrap_or("unresolved cookie"),
                a.decision
            ),
            finding_id: Some(a.finding.id.clone()),
            location: a.finding.evidence.iter().find_map(|e| e.location.clone()),
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedBehaviour {
    pub cookie: CookieIdentity,
    pub operation: Operation,
    pub technical_classification: String,
    pub permission: PermissionClass,
    pub decision: Decision,
    pub source_hashes: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLock {
    pub schema_version: u32,
    pub application: String,
    pub policy_sha256: String,
    pub behaviours: BTreeMap<String, LockedBehaviour>,
    pub checksum: String,
}
impl PolicyLock {
    pub fn new(
        application: &str,
        policy_sha256: &str,
        items: &[Assessment],
    ) -> Result<Self, String> {
        let mut behaviours = BTreeMap::new();
        for a in items {
            let f = &a.finding;
            let record = LockedBehaviour {
                cookie: f.cookie.clone(),
                operation: f.operation,
                technical_classification: f.technical_classification.clone(),
                permission: f.classification.value,
                decision: a.decision,
                source_hashes: f
                    .evidence
                    .iter()
                    .map(|e| e.content_sha256.clone())
                    .collect(),
            };
            if behaviours.insert(f.id.clone(), record).is_some() {
                return Err("duplicate behaviour identity".into());
            }
        }
        let mut lock = Self {
            schema_version: SCHEMA_VERSION,
            application: application.into(),
            policy_sha256: policy_sha256.into(),
            behaviours,
            checksum: String::new(),
        };
        lock.checksum = lock.calculate_checksum()?;
        Ok(lock)
    }
    fn calculate_checksum(&self) -> Result<String, String> {
        serde_json::to_vec(&(
            self.schema_version,
            &self.application,
            &self.policy_sha256,
            &self.behaviours,
        ))
        .map(|bytes| sha256(&bytes))
        .map_err(|e| e.to_string())
    }
    pub fn parse(text: &str) -> Result<Self, String> {
        let lock: Self =
            serde_json::from_str(text).map_err(|e| format!("invalid policy lock: {e}"))?;
        if lock.schema_version != SCHEMA_VERSION {
            return Err("unsupported lock schema_version".into());
        }
        if lock.checksum != lock.calculate_checksum()? {
            return Err("policy lock checksum mismatch".into());
        }
        Ok(lock)
    }
    pub fn compare(&self, current: &Self) -> Vec<Diagnostic> {
        let mut changes = Vec::new();
        let diagnostic = |code: &str, message: String, id: Option<String>| Diagnostic {
            code: code.into(),
            message,
            finding_id: id,
            location: None,
        };
        if self.application != current.application {
            changes.push(diagnostic(
                "CRUMBLED_APPLICATION_CHANGED",
                "Application identity differs from the approved lock".into(),
                None,
            ));
        }
        if self.policy_sha256 != current.policy_sha256 {
            changes.push(diagnostic(
                "CRUMBLED_POLICY_CHANGED",
                "Policy differs from the approved lock".into(),
                None,
            ));
        }
        for (id, behaviour) in &current.behaviours {
            match self.behaviours.get(id) {
                None => changes.push(diagnostic(
                    "CRUMBLED_NEW_BEHAVIOUR",
                    "New unapproved cookie behaviour".into(),
                    Some(id.clone()),
                )),
                Some(old) if old != behaviour => changes.push(diagnostic(
                    "CRUMBLED_CHANGED_BEHAVIOUR",
                    "Cookie identity, source, purpose, or permission changed".into(),
                    Some(id.clone()),
                )),
                _ => {}
            }
        }
        for id in self
            .behaviours
            .keys()
            .filter(|id| !current.behaviours.contains_key(*id))
        {
            changes.push(diagnostic(
                "CRUMBLED_REMOVED_BEHAVIOUR",
                "Previously approved cookie behaviour was removed".into(),
                Some(id.clone()),
            ));
        }
        changes
    }
}

/// Atomic, single-file replacement. Call only following explicit lock approval.
pub fn write_lock(root: &Path, lock: &PolicyLock) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("policy lock target must be a regular directory".into());
    }
    let destination = root.join("crumbled.lock");
    match fs::symlink_metadata(&destination) {
        Ok(m) if !m.is_file() => {
            return Err("refusing to replace a symlink or non-file policy lock".into());
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
        _ => {}
    }
    let bytes = serde_json::to_vec_pretty(lock).map_err(|e| e.to_string())?;
    // Serialize and validate before any filesystem mutation.
    PolicyLock::parse(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
    if fs::read(&destination).ok().as_deref() == Some(&bytes) {
        return Ok(());
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temporary = root.join(format!(
        ".crumbled-lock-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        fs::rename(&temporary, &destination).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksums_and_versions_are_validated() {
        let lock = PolicyLock::new("shop", "hash", &[]).unwrap();
        let json = serde_json::to_string(&lock).unwrap();
        assert_eq!(PolicyLock::parse(&json).unwrap(), lock);
        assert!(PolicyLock::parse(&json.replace("shop", "other")).is_err());
        assert!(
            PolicyLock::parse(&json.replace("\"schema_version\":1", "\"schema_version\":2"))
                .is_err()
        );
    }
    #[test]
    fn plans_never_claim_to_enforce() {
        let plan = compile(&[]);
        assert!(!plan.applicable);
        assert!(plan.changes.is_empty());
        assert_eq!(plan, compile(&[]));
    }
}
