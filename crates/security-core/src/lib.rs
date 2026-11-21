pub mod review;
pub mod ai;
mod scanner;
mod store;
pub use scanner::{scan, Finding, Manifest, ProjectScope, Scan};
use serde_json::{json, Value};
pub use store::{try_default_db, ScanSummary, Store};

fn verification(f: &Finding) -> &'static str {
    match f.category.as_str() {
        "dependency" => "version_matched",
        "coverage" => "analysis_incomplete",
        _ => "unverified_static_observation",
    }
}
pub fn json_report(scan: &Scan) -> Value {
    let mut report = json!(scan);
    report["schema_version"] = json!(1);
    let limited =
        !scan.diagnostics.is_empty() || !scan.warnings.is_empty();
    report["coverage_status"] = json!(if limited {
        "limited"
    } else {
        "completed_within_rule_scope"
    });
    for (index, f) in scan.findings.iter().enumerate() {
        let finding = &mut report["findings"][index];
        finding["finding_id"] = json!(format!("{}:{index}", scan.id));
        finding["scan_id"] = json!(scan.id);
        finding["observed_at_unix"] = json!(scan.created_at);
        finding["severity_source"] = json!("Helinity local review priority");
        finding["verification_status"] = json!(verification(f));
    }
    report
}
fn location(f: &Finding) -> Value {
    let mut uri = String::new();
    for &b in f.path.as_bytes() {
        if b.is_ascii_alphanumeric() || b"/-_.~".contains(&b) {
            uri.push(char::from(b));
        } else {
            use std::fmt::Write;
            let _ = write!(uri, "%{b:02X}");
        }
    }
    let mut physical = json!({"artifactLocation":{"uri":uri}});
    if f.line > 0 && f.column > 0 {
        let mut region = json!({"startLine":f.line,"startColumn":f.column});
        if f.end_line >= f.line && f.end_column > 0 {
            region["endLine"] = json!(f.end_line);
            region["endColumn"] = json!(f.end_column);
        }
        if let Some(snippet) = &f.source_context {
            region["snippet"] = json!({"text":snippet});
        }
        physical["region"] = region;
    }
    json!({"physicalLocation":physical})
}
pub fn sarif(scan: &Scan) -> Value {
    let results: Vec<_> = scan.findings.iter().enumerate().map(|(index,f)| {
        let level=match f.severity.as_str(){"high"=>"error","medium"=>"warning",_=>"note"};
        json!({"ruleId":f.id,"level":level,"message":{"text":f.explanation},"locations":[location(f)],
          "properties":{"analyzer":f.tool,"cwe":f.cwe,"confidence":f.confidence,"category":f.category,
          "findingId":format!("{}:{index}",scan.id),"observedAtUnix":scan.created_at,
          "severitySource":"Helinity local review priority","reviewStatus":verification(f),"evidence":f.evidence,"guidance":f.remediation}})
    }).collect();
    let mut notices: Vec<_> = scan
        .diagnostics
        .iter()
        .map(|text| json!({"level":"note","message":{"text":text}}))
        .collect();
    notices.extend(scan.warnings.iter().map(|w| json!({
        "level":"warning","descriptor":{"id":w.id},"message":{"text":w.explanation},
        "locations":[location(w)]
    })));
    json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{
        "tool":{"driver":{"name":"Helinity","version":env!("CARGO_PKG_VERSION")}},
        "columnKind":"utf16CodeUnits","invocations":[{"executionSuccessful":true,"toolExecutionNotifications":notices}],"results":results}]})
}
