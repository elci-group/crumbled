use crumbled_core::{CookieIdentity, Decision, PermissionClass};
use crumbled_discovery::scan_text;
use crumbled_policy::{Policy, PolicyRule};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Repository(PathBuf);
impl Repository {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crumbled-contract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, path: &str, content: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_crumbled"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
    fn json(&self, args: &[&str], exit: i32) -> Value {
        let mut args = args.to_vec();
        args.extend(["--format", "json"]);
        let output = self.run(&args);
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn policy(&self, source: &str, category: PermissionClass) {
        let cookie = scan_text("app.js", source, "application", None)[0]
            .cookie
            .clone();
        let policy = Policy {
            rules: vec![PolicyRule {
                cookie,
                category,
                reason: "Reviewed by the application owner".into(),
            }],
            ..Policy::default()
        };
        self.write(
            "crumbled.policy.json",
            &serde_json::to_string_pretty(&policy).unwrap(),
        );
    }
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, files);
                } else {
                    files.insert(path.clone(), fs::read(path).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        walk(&self.0, &mut files);
        files
    }
}
impl Drop for Repository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const COOKIE: &str = "document.cookie = 'session_id=synthetic; Domain=.example.test; Path=/';";
#[test]
fn scan_is_read_only_and_names_never_implicitly_allow() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    let before = r.snapshot();
    let report = r.json(&["scan", "--application", "shop", "."], 0);
    assert_eq!(report["assessments"][0]["decision"], "block");
    assert_eq!(
        report["assessments"][0]["finding"]["classification"]["value"],
        "unknown"
    );
    assert_eq!(report["assessments"][0]["finding"]["observed"], false);
    assert_eq!(
        report["assessments"][0]["finding"]["cookie"]["domain"],
        "example.test"
    );
    assert!(
        report["assessments"][0]["finding"]["evidence"][0]["content_sha256"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
    r.json(&["audit"], 1);
    assert_eq!(before, r.snapshot());
}
#[test]
fn output_options_do_not_become_paths_and_single_files_work() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    let output = r.run(&["scan", "--format", "json"]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["assessments"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    r.json(&["scan", "app.js"], 0);
    r.json(&["scan", "--policy"], 2);
    r.json(&["scan", "--bogus"], 2);
    assert_eq!(r.run(&["scan", "--format", "xml"]).status.code(), Some(2));
    r.json(&["scan", "absent"], 2);
    r.json(&["enforce", "--apply", "--dry-run"], 2);
}
#[test]
fn preview_and_unsupported_apply_do_not_modify_any_file() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.write(".crumbled/enforcement.json", "old artifact");
    let before = r.snapshot();
    let report = r.json(&["enforce"], 0);
    assert_eq!(report["artifact"]["applicable"], false);
    assert_eq!(report["artifact"]["gates"][0]["compiled"], false);
    assert_eq!(report["artifact"]["gates"][0]["default_state"], "blocked");
    r.json(&["enforce", "--strict", "--dry-run"], 0);
    r.json(&["enforce", "--strict", "--apply"], 3);
    r.json(&["lock"], 0);
    assert_eq!(before, r.snapshot());
}
#[test]
fn explicit_policy_and_reviewed_lock_are_required_for_static_success() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.json(&["verify"], 1);
    r.policy(COOKIE, PermissionClass::Necessary);
    let report = r.json(&["scan"], 0);
    assert_eq!(report["assessments"][0]["decision"], "allow");
    assert_eq!(
        report["assessments"][0]["finding"]["classification"]["method"],
        "user_policy"
    );
    assert_eq!(report["assessments"][0]["gated"], false);
    r.json(&["verify"], 1);
    r.json(&["lock", "--approve"], 0);
    r.json(&["verify"], 0);
    let first = fs::read(r.0.join("crumbled.lock")).unwrap();
    let modified = fs::metadata(r.0.join("crumbled.lock"))
        .unwrap()
        .modified()
        .unwrap();
    r.json(&["lock", "--approve"], 0);
    assert_eq!(first, fs::read(r.0.join("crumbled.lock")).unwrap());
    assert_eq!(
        modified,
        fs::metadata(r.0.join("crumbled.lock"))
            .unwrap()
            .modified()
            .unwrap()
    );
}
#[test]
fn inventory_approval_does_not_satisfy_consent_or_block_decisions() {
    for category in [
        PermissionClass::Preferences,
        PermissionClass::Analytics,
        PermissionClass::Marketing,
        PermissionClass::Unknown,
    ] {
        let r = Repository::new();
        r.write("app.js", COOKIE);
        r.policy(COOKIE, category);
        r.json(&["lock", "--approve"], 0);
        let report = r.json(&["verify", "--strict"], 1);
        assert!(!report["diagnostics"].as_array().unwrap().is_empty());
        assert_eq!(report["assessments"][0]["gated"], false);
    }
}
#[test]
fn exact_identity_policy_does_not_leak_across_domains_or_modules() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.policy(COOKIE, PermissionClass::Necessary);
    r.write("other.js", &COOKIE.replace("example.test", "other.test"));
    let report = r.json(&["scan"], 0);
    assert_eq!(report["assessments"][0]["decision"], "allow");
    assert_eq!(report["assessments"][1]["decision"], "block");
    let id: CookieIdentity =
        serde_json::from_value(report["assessments"][0]["finding"]["cookie"].clone()).unwrap();
    let policy = Policy {
        rules: vec![
            PolicyRule {
                cookie: id.clone(),
                category: PermissionClass::Necessary,
                reason: "reviewed".into(),
            },
            PolicyRule {
                cookie: id,
                category: PermissionClass::Marketing,
                reason: "contradictory".into(),
            },
        ],
        ..Policy::default()
    };
    r.write(
        "crumbled.policy.json",
        &serde_json::to_string(&policy).unwrap(),
    );
    r.json(&["scan"], 2);
}
#[test]
fn drift_detects_added_removed_changed_source_and_changed_policy() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.policy(COOKIE, PermissionClass::Necessary);
    r.json(&["lock", "--approve"], 0);
    r.write("app.js", &format!("{COOKIE}\n// changed source"));
    let report = r.json(&["verify"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "CRUMBLED_CHANGED_BEHAVIOUR")
    );
    r.write("app.js", COOKIE);
    r.write("added.js", "cookieStore.set('tracking', 'synthetic');");
    let report = r.json(&["verify"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "CRUMBLED_NEW_BEHAVIOUR")
    );
    fs::remove_file(r.0.join("added.js")).unwrap();
    r.write("app.js", "");
    let report = r.json(&["verify"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "CRUMBLED_REMOVED_BEHAVIOUR")
    );
    r.write("app.js", COOKIE);
    r.policy(COOKIE, PermissionClass::Analytics);
    let report = r.json(&["verify"], 1);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "CRUMBLED_POLICY_CHANGED")
    );
}
#[test]
fn lock_corruption_is_an_integrity_failure() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.policy(COOKIE, PermissionClass::Necessary);
    r.json(&["lock", "--approve"], 0);
    let lock = fs::read_to_string(r.0.join("crumbled.lock")).unwrap();
    r.write(
        "crumbled.lock",
        &lock.replace("example.test", "corrupted.test"),
    );
    let report = r.json(&["verify"], 3);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "CRUMBLED_INTEGRITY_FAILURE")
    );
}
#[test]
fn explain_uses_subject_and_root_separately_and_graph_references_resolve() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    let report = r.json(&["scan"], 0);
    let id = report["assessments"][0]["finding"]["id"].as_str().unwrap();
    let explained = r.json(&["explain", id, "--root", "."], 0);
    assert_eq!(explained["assessments"], report["assessments"]);
    r.json(&["explain", "--why-blocked", "session_id"], 0);
    r.json(&["explain", "absent"], 1);
    let nodes = report["graph"]["nodes"].as_array().unwrap();
    for edge in report["graph"]["edges"].as_array().unwrap() {
        assert!(nodes.iter().any(|node| node["id"] == edge["from"]));
        assert!(nodes.iter().any(|node| node["id"] == edge["to"]));
    }
}
#[test]
fn machine_formats_include_failures_and_evidence() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    for format in ["json", "jsonl", "sarif"] {
        for command in ["scan", "audit", "enforce", "observe", "verify"] {
            let output = r.run(&[command, "--format", format]);
            let text = String::from_utf8(output.stdout).unwrap();
            if format == "jsonl" {
                for line in text.lines() {
                    serde_json::from_str::<Value>(line).unwrap();
                }
            } else {
                serde_json::from_str::<Value>(&text).unwrap();
            }
        }
    }
    let output = r.run(&["audit", "--format", "sarif"]);
    let sarif: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app.js"
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
}
#[test]
fn relocation_preserves_ids_and_locks_and_scans_are_sorted() {
    let a = Repository::new();
    let b = Repository::new();
    for r in [&a, &b] {
        r.write("z.js", COOKIE);
        r.write("a.js", "cookieStore.set('a', 'b');");
    }
    let a_report = a.json(&["lock"], 0);
    let b_report = b.json(&["lock"], 0);
    assert_eq!(a_report["artifact"], b_report["artifact"]);
    assert_eq!(
        a_report["assessments"][0]["finding"]["evidence"][0]["location"]["path"],
        "a.js"
    );
}
#[test]
fn oversized_invalid_utf8_and_missing_policy_are_analysis_failures() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    r.json(&["scan", "--policy", "absent.json"], 2);
    fs::write(r.0.join("app.js"), [255, 254]).unwrap();
    r.json(&["scan"], 2);
    r.write(
        "app.js",
        &"x".repeat(crumbled_discovery::MAX_SOURCE_BYTES as usize + 1),
    );
    r.json(&["scan"], 2);
}
#[cfg(unix)]
#[test]
fn symlink_loops_and_lock_symlinks_fail_without_writes() {
    use std::os::unix::fs::symlink;
    let r = Repository::new();
    r.write("app.js", COOKIE);
    symlink(&r.0, r.0.join("loop")).unwrap();
    r.json(&["scan"], 2);
    fs::remove_file(r.0.join("loop")).unwrap();
    let outside = Repository::new();
    outside.write("approved.json", "do not touch");
    symlink(outside.0.join("approved.json"), r.0.join("crumbled.lock")).unwrap();
    r.json(&["lock", "--approve"], 3);
    r.json(&["verify"], 3);
    assert_eq!(
        fs::read_to_string(outside.0.join("approved.json")).unwrap(),
        "do not touch"
    );
}
#[test]
fn unknown_cannot_be_configured_to_allow() {
    let r = Repository::new();
    r.write("app.js", COOKIE);
    let mut policy = Policy::default();
    policy
        .decisions
        .insert(PermissionClass::Unknown, Decision::Allow);
    r.write(
        "crumbled.policy.json",
        &serde_json::to_string(&policy).unwrap(),
    );
    r.json(&["enforce", "--apply"], 2);
    assert!(!r.0.join(".crumbled").exists());
    r.write(
        "crumbled.policy.json",
        &json!({"schema_version":1, "rules":[], "silent_allow":true}).to_string(),
    );
    r.json(&["scan"], 2);
}

#[test]
fn canonical_fixture_corpus_and_example_policy_work_together() {
    let browser = include_str!("../../../fixtures/browser/basic.js");
    let server = include_str!("../../../fixtures/server/headers.py");
    let findings = scan_text("basic.js", browser, "application", None);
    assert_eq!(findings.len(), 5);
    let policy = Policy::from_json(include_str!("../../../policies/example.json")).unwrap();
    let assessments = policy.assess_all(findings, None).unwrap();
    assert_eq!(assessments[0].decision, Decision::Gate);
    assert_eq!(
        assessments[0].finding.classification.value,
        PermissionClass::Preferences
    );
    assert_eq!(
        scan_text("headers.py", server, "application", None).len(),
        2
    );
}
