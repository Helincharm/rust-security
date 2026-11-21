use crate::Scan;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Instant;

/// Query a saved scan only. Source text never participates in instruction selection.
pub fn investigate(scan: &Scan, question: &str) -> Result<Value, String> {
    if question.trim().is_empty() || question.len() > 2048 {
        return Err("Enter a question within 2048 bytes".into());
    }
    let start = Instant::now();
    let terms: Vec<_> = question
        .split_whitespace()
        .take(64)
        .map(|s| {
            s.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .collect();
    let mut ranked: Vec<_> = scan
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let fields = format!(
                "{} {} {} {} {} {}",
                f.id,
                f.path,
                f.tool,
                f.severity,
                f.cwe.as_deref().unwrap_or(""),
                f.explanation
            )
            .to_lowercase();
            let count = terms
                .iter()
                .filter(|t| t.len() > 2 && fields.contains(t.as_str()))
                .count();
            (std::cmp::Reverse(count), i, f)
        })
        .collect();
    ranked.retain(|(rank, _, _)| rank.0 > 0);
    ranked.sort_by_key(|(rank, index, _)| (*rank, *index));
    let events = json!([{"tool":"search_saved_observations","duration_ms":start.elapsed().as_millis(),"status":"completed","summary":format!("Matched {} saved observations",ranked.len())}]);
    let refs: Vec<_> = ranked
        .iter()
        .take(5)
        .map(|(_, i, f)| json!({"index":i,"path":f.path,"line":f.line,"rule":f.id}))
        .collect();
    let answer = ranked
        .iter()
        .take(5)
        .map(|(_, _, f)| {
            format!(
                "{}:{} [{}] {} {}",
                f.path, f.line, f.id, f.explanation, f.remediation
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(
        json!({"provider":"local evidence","answer":if answer.is_empty(){"No saved observations matched this question.".into()}else{answer},"events":events,"references":refs}),
    )
}

/// A multiset comparison preserves duplicate observations and ignores line-only shifts.
pub fn compare(a: &Scan, b: &Scan) -> Result<Value, String> {
    if a.project != b.project {
        return Err("Cannot compare scans from different projects".into());
    }

    // Signed delta per (path, id, tool): after-count minus before-count.
    // source_context is deliberately excluded from the key and the output.
    let mut deltas: BTreeMap<(String, String, String), i64> = BTreeMap::new();

    for f in &a.findings {
        let entry = deltas
            .entry((f.path.clone(), f.id.clone(), f.tool.clone()))
            .or_insert(0);
        *entry = entry.saturating_sub(1);
    }
    for f in &b.findings {
        let entry = deltas
            .entry((f.path.clone(), f.id.clone(), f.tool.clone()))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    // BTreeMap iteration is sorted by (path, id, tool), so output order is deterministic.
    let changes: Vec<Value> = deltas
        .into_iter()
        .filter(|(_, delta)| *delta != 0)
        .map(|((path, rule, tool), count_delta)| {
            json!({
                "path": path,
                "rule": rule,
                "tool": tool,
                "count_delta": count_delta,
            })
        })
        .collect();

    Ok(json!({
        "before": {
            "id": a.id,
            "finding_count": a.findings.len(),
        },
        "after": {
            "id": b.id,
            "finding_count": b.findings.len(),
        },
        "changes": changes,
        "before_diagnostic_count": a.diagnostics.len(),
        "after_diagnostic_count": b.diagnostics.len(),
        "interpretation": "count_delta values are observed differences in reported findings between two scans; they are observations only and do not confirm that any issue was fixed or introduced. A negative delta may come from changes in tool configuration, coverage, diagnostics, or code movement, not from a verified fix.",
    }))
}
