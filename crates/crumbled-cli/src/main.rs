use crumbled_core::{CookieGraph, Report};
use crumbled_discovery::{read_bounded, scan_repository};
use crumbled_enforce::{PolicyLock, compile, violations, write_lock};
use crumbled_policy::Policy;
use crumbled_report::{Format, render};
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::UNIX_EPOCH,
};

#[derive(Debug)]
struct Args {
    command: String,
    root: PathBuf,
    application: String,
    format: Format,
    policy: Option<PathBuf>,
    subject: Option<String>,
    apply: bool,
    approve: bool,
    why_blocked: bool,
}
impl Args {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let command = arguments.first().ok_or("missing command")?.as_str();
        if ![
            "scan", "audit", "verify", "enforce", "explain", "lock", "observe",
        ]
        .contains(&command)
        {
            return Err(format!("unknown command: {command}"));
        }
        let mut result = Self {
            command: command.into(),
            root: PathBuf::from("."),
            application: "application".into(),
            format: Format::Human,
            policy: None,
            subject: None,
            apply: false,
            approve: false,
            why_blocked: false,
        };
        let mut i = 1;
        let mut positional = Vec::new();
        let mut dry_run = false;
        let mut explicit_root = false;
        while i < arguments.len() {
            let arg = &arguments[i];
            if arg == "--" {
                positional.extend(arguments[i + 1..].iter().cloned());
                break;
            }
            match arg.as_str() {
                "--format" | "--application" | "--policy" | "--root" => {
                    i += 1;
                    let value = arguments
                        .get(i)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    match arg.as_str() {
                        "--format" => result.format = Format::parse(value)?,
                        "--application" => {
                            if value.trim().is_empty() {
                                return Err("application must not be empty".into());
                            }
                            result.application = value.clone();
                        }
                        "--policy" => result.policy = Some(PathBuf::from(value)),
                        _ => {
                            result.root = PathBuf::from(value);
                            explicit_root = true;
                        }
                    }
                }
                "--apply" if command == "enforce" => result.apply = true,
                "--approve" if command == "lock" => result.approve = true,
                "--dry-run" if command == "enforce" || command == "lock" => dry_run = true,
                "--strict" if command == "enforce" || command == "verify" => {}
                "--why-blocked" if command == "explain" => result.why_blocked = true,
                value if value.starts_with('-') => {
                    return Err(format!("unsupported option for {command}: {value}"));
                }
                _ => positional.push(arg.clone()),
            }
            i += 1;
        }
        if dry_run && (result.apply || result.approve) {
            return Err("--dry-run conflicts with mutation authority".into());
        }
        if command == "explain" {
            if positional.len() != 1 {
                return Err("explain requires one finding ID, cookie ID, or exact cookie name; use --root for the repository".into());
            }
            result.subject = positional.pop();
        } else {
            if positional.len() > 1 || (explicit_root && !positional.is_empty()) {
                return Err("expected one repository path".into());
            }
            if let Some(path) = positional.pop() {
                result.root = PathBuf::from(path);
            }
        }
        Ok(result)
    }
}
fn run(args: &Args) -> Report {
    let mut report = Report::new(&args.command, &args.application, vec![]);
    if args.command == "observe" {
        report.diagnostic(
            "CRUMBLED_ANALYSIS_FAILURE",
            "Browser observation is not implemented in this build",
            2,
        );
        return report;
    }
    let result = (|| {
        let policy_root = if args.root.is_file() {
            args.root.parent().unwrap_or(std::path::Path::new("."))
        } else {
            &args.root
        };
        let policy_path = args
            .policy
            .clone()
            .unwrap_or_else(|| policy_root.join("crumbled.policy.json"));
        let (policy, timestamp) = match fs::symlink_metadata(&policy_path) {
            Ok(metadata) => {
                let policy = Policy::from_json(&read_bounded(&policy_path)?)?;
                let timestamp = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|t| t.as_secs());
                (policy, timestamp)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && args.policy.is_none() => {
                (Policy::default(), None)
            }
            Err(e) => return Err(format!("{}: {e}", policy_path.display())),
        };
        let findings = scan_repository(&args.root, &args.application)?;
        let assessments = policy.assess_all(findings, timestamp)?;
        Ok((policy, assessments))
    })();
    let (policy, assessments) = match result {
        Ok(value) => value,
        Err(error) => {
            report.diagnostic("CRUMBLED_ANALYSIS_FAILURE", error, 2);
            return report;
        }
    };
    report.assessments = assessments;
    report.graph = CookieGraph::from_assessments(&report.assessments);
    match args.command.as_str() {
        "scan" => {}
        "audit" => {
            report.diagnostics = violations(&report.assessments);
            if !report.diagnostics.is_empty() {
                report.exit_code = 1;
            }
        }
        "explain" => {
            let subject = args.subject.as_deref().unwrap_or("");
            report.assessments.retain(|a| {
                a.finding.id == subject
                    || a.finding.cookie.id() == subject
                    || a.finding.cookie.name.as_deref() == Some(subject)
            });
            report.graph = CookieGraph::from_assessments(&report.assessments);
            if report.assessments.is_empty() {
                report.diagnostic(
                    "CRUMBLED_FINDING_NOT_FOUND",
                    "No matching finding in this repository",
                    1,
                );
            } else if args.why_blocked {
                report.diagnostics = violations(&report.assessments);
            }
        }
        "enforce" => {
            let plan = compile(&report.assessments);
            report.artifact = serde_json::to_value(plan).ok();
            if args.apply {
                report.diagnostic("CRUMBLED_ENFORCEMENT_UNSUPPORTED", "No execution-path compiler is available; validation failed and no files were modified", 3);
            }
        }
        "lock" | "verify" => process_lock(args, &policy, &mut report),
        _ => {}
    }
    report
}
fn process_lock(args: &Args, policy: &Policy, report: &mut Report) {
    let current = policy
        .fingerprint()
        .and_then(|hash| PolicyLock::new(&args.application, &hash, &report.assessments));
    let current = match current {
        Ok(lock) => lock,
        Err(e) => {
            report.diagnostic("CRUMBLED_ANALYSIS_FAILURE", e, 2);
            return;
        }
    };
    if args.command == "lock" {
        report.artifact = serde_json::to_value(&current).ok();
        if args.approve
            && let Err(e) = write_lock(&args.root, &current)
        {
            report.diagnostic("CRUMBLED_INTEGRITY_FAILURE", e, 3);
        }
        return;
    }
    report.diagnostics = violations(&report.assessments);
    if !report.diagnostics.is_empty() {
        report.exit_code = 1;
    }
    let path = args.root.join("crumbled.lock");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => report.diagnostic("CRUMBLED_LOCK_MISSING", "No approved topology; review `crumbled lock` and approve with `crumbled lock --approve`", 1),
        Err(e) => report.diagnostic("CRUMBLED_INTEGRITY_FAILURE", e.to_string(), 3),
        Ok(_) => match read_bounded(&path).and_then(|text| PolicyLock::parse(&text)) {
            Err(e) => report.diagnostic("CRUMBLED_INTEGRITY_FAILURE", e, 3),
            Ok(approved) => { let changes = approved.compare(&current); if !changes.is_empty() { report.exit_code = 1; report.diagnostics.extend(changes); } }
        }
    }
}
fn main() -> ExitCode {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.is_empty() || arguments.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if arguments == ["--version"] {
        println!("crumbled {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let (report, format) = match Args::parse(&arguments) {
        Ok(args) => (run(&args), args.format),
        Err(error) => {
            let mut report = Report::new(
                arguments.first().map(String::as_str).unwrap_or(""),
                "application",
                vec![],
            );
            report.diagnostic("CRUMBLED_ARGUMENT_ERROR", error, 2);
            let format = arguments
                .windows(2)
                .find(|a| a[0] == "--format")
                .and_then(|a| Format::parse(&a[1]).ok())
                .unwrap_or(Format::Human);
            (report, format)
        }
    };
    match render(&report, format) {
        Ok(output) => {
            if let Err(error) = writeln!(io::stdout().lock(), "{output}")
                && error.kind() != io::ErrorKind::BrokenPipe
            {
                eprintln!("report output failed: {error}");
                return ExitCode::from(2);
            }
        }
        Err(error) => {
            eprintln!("report serialization failed: {error}");
            return ExitCode::from(2);
        }
    }
    ExitCode::from(report.exit_code)
}
const HELP: &str = "crumbled <scan|audit|verify|enforce|explain|lock|observe> [path] [options]\n\n  --format human|json|jsonl|sarif\n  --application NAME        Stable application identity (default: application)\n  --policy FILE             Explicit JSON policy; otherwise crumbled.policy.json\n  --root PATH               Repository for explain (default: .)\n  enforce [--dry-run]        Preview abstract gates (default; no mutation)\n  enforce --apply           Requires a complete compiler; currently fails with 3\n  lock [--dry-run]           Preview topology approval\n  lock --approve            Atomically write or update crumbled.lock\n  explain ID_OR_NAME         Show all matching findings and their evidence\n  explain --why-blocked NAME Show the unresolved permission boundary\n  --strict                  Accepted for enforce/verify; unknown is always blocked\n\nverify: 0 = reviewed static topology and no unresolved policy violations\n        1 = policy/topology violation, 2 = analysis failure, 3 = integrity failure\nA successful static check does not attest runtime enforcement.\nobserve and execution-path compilation are not implemented in this build.\n";
