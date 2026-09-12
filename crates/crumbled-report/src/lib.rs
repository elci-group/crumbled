//! All formats derive from one report, including command failures and evidence.
use crumbled_core::{Diagnostic, Report};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    Human,
    Json,
    Jsonl,
    Sarif,
}
impl Format {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            "sarif" => Ok(Self::Sarif),
            _ => Err(format!("unsupported output format: {value}")),
        }
    }
}
pub fn render(report: &Report, format: Format) -> Result<String, String> {
    match format {
        Format::Json => serde_json::to_string_pretty(report).map_err(|e| e.to_string()),
        Format::Jsonl => {
            let mut lines = Vec::new();
            lines.push(json!({"event":"analysis_started", "command":report.command, "schema_version":report.schema_version}));
            for a in &report.assessments {
                lines.push(json!({"event":"cookie_discovered", "assessment":a}));
            }
            for diagnostic in &report.diagnostics {
                lines.push(json!({"event":"diagnostic", "diagnostic":diagnostic}));
            }
            lines.push(json!({"event":"analysis_finished", "report":report}));
            lines
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .map(|lines| lines.join("\n"))
                .map_err(|e| e.to_string())
        }
        Format::Sarif => serde_json::to_string_pretty(&sarif(report)).map_err(|e| e.to_string()),
        Format::Human => {
            let mut text = format!(
                "CRUMBLED — {}\n{} declared behaviour(s); 0 runtime observations\n{}\n",
                report.command.escape_debug(),
                report.assessments.len(),
                report.analysis_scope
            );
            for a in &report.assessments {
                let name = a.finding.cookie.name.as_deref().unwrap_or("unresolved");
                text.push_str(&format!(
                    "{}  {:?} → {:?} ({:?})\n  {}\n",
                    name.escape_debug(),
                    a.finding.operation,
                    a.decision,
                    a.finding.classification.value,
                    a.finding.id
                ));
                for ev in a
                    .finding
                    .evidence
                    .iter()
                    .chain(&a.finding.classification.evidence)
                {
                    let location = ev
                        .location
                        .as_ref()
                        .map(|l| format!("{}:{}:{}", l.path.display(), l.line, l.column))
                        .unwrap_or_else(|| ev.source.clone());
                    text.push_str(&format!(
                        "  {}: {}\n",
                        location.escape_debug(),
                        ev.detail.escape_debug()
                    ));
                }
            }
            for d in &report.diagnostics {
                text.push_str(&format!(
                    "{}: {}\n",
                    d.code.escape_debug(),
                    d.message.escape_debug()
                ));
            }
            if let Some(artifact) = &report.artifact {
                text.push_str(&serde_json::to_string_pretty(artifact).map_err(|e| e.to_string())?);
                text.push('\n');
            }
            text.push_str(&format!("Exit status: {}\n", report.exit_code));
            Ok(text)
        }
    }
}
fn sarif(report: &Report) -> Value {
    let mut diagnostics = report.diagnostics.clone();
    if report.command == "scan" || report.command == "explain" {
        for a in &report.assessments {
            diagnostics.push(Diagnostic {
                code: "CRUMBLED_DISCOVERED".into(),
                message: format!("{:?}: {}", a.finding.operation, a.reason),
                finding_id: Some(a.finding.id.clone()),
                location: a.finding.evidence.iter().find_map(|e| e.location.clone()),
            });
        }
    }
    let results: Vec<_> = diagnostics.iter().map(|d| {
        let mut result = json!({"ruleId":d.code, "level":if d.code == "CRUMBLED_DISCOVERED" { "note" } else { "error" }, "message":{"text":d.message}, "properties":{"finding_id":d.finding_id}});
        if let Some(location) = &d.location {
            result["locations"] = json!([{"physicalLocation":{"artifactLocation":{"uri":uri(&location.path.to_string_lossy())}, "region":{"startLine":location.line,"startColumn":location.column}}}]);
        }
        result
    }).collect();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json", "version":"2.1.0", "runs":[{"tool":{"driver":{"name":"crumbled","version":env!("CARGO_PKG_VERSION")}}, "columnKind":"unicodeCodePoints", "invocations":[{"executionSuccessful":report.exit_code < 2, "exitCode":report.exit_code}], "results":results, "properties":{"crumbled":report}}]})
}
fn uri(path: &str) -> String {
    let mut result = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_machine_formats_escape_untrusted_text() {
        let mut report = Report::new("scan", "quote\"\n\t\u{0001}", vec![]);
        report.diagnostic("analysis_failure", "line\n\"quoted\"\u{0001}", 2);
        for format in [Format::Json, Format::Jsonl, Format::Sarif] {
            let output = render(&report, format).unwrap();
            if format == Format::Jsonl {
                for line in output.lines() {
                    serde_json::from_str::<Value>(line).unwrap();
                }
            } else {
                serde_json::from_str::<Value>(&output).unwrap();
            }
        }
        let output = sarif(&report);
        assert_eq!(
            output["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(uri("src/a b#c.js"), "src/a%20b%23c.js");
    }
}
