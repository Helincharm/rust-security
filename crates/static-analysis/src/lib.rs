use serde::{Deserialize, Serialize};
use std::ops::Range;

mod ast;
mod lock;

pub use ast::analyze_source;
pub use lock::analyze_lock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub tool: String,
    pub path: String,
    pub cwe: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub explanation: String,
    pub remediation: String,
    pub evidence: String,
    #[serde(default)]
    pub source_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<String>,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

const MAX_FINDINGS: usize = 512;
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_LINE_BYTES: usize = 512;

#[derive(Clone, Copy)]
struct Rule<'a> {
    id: &'a str,
    cwe: Option<&'static str>,
    severity: &'static str,
    confidence: &'static str,
    explanation: &'static str,
    remediation: &'static str,
}

struct Report<'a> {
    path: &'a str,
    source: &'a str,
    tool: &'static str,
    category: &'static str,
    line_starts: Vec<usize>,
    findings: Vec<Finding>,
    omitted: bool,
}

impl<'a> Report<'a> {
    fn new(path: &'a str, source: &'a str, tool: &'static str, category: &'static str) -> Self {
        let mut line_starts = vec![0];
        if source.len() <= MAX_INPUT_BYTES {
            line_starts.extend(
                source
                    .bytes()
                    .enumerate()
                    .filter_map(|(i, byte)| (byte == b'\n').then_some(i + 1)),
            );
        }
        Self {
            path,
            source,
            tool,
            category,
            line_starts,
            findings: Vec::new(),
            omitted: false,
        }
    }

    fn position(&self, offset: usize) -> (u32, u32) {
        let line = self.line_starts.partition_point(|start| *start <= offset) - 1;
        let column = self.source[self.line_starts[line]..offset]
            .encode_utf16()
            .count();
        ((line + 1) as u32, (column + 1) as u32)
    }

    fn snapshot_line(&self, line: u32) -> Option<String> {
        let index = usize::try_from(line.checked_sub(1)?).ok()?;
        let start = *self.line_starts.get(index)?;
        let end = self.line_starts.get(index + 1).copied().unwrap_or(self.source.len());
        let text = self.source.get(start..end)?.trim_end_matches(['\r', '\n']);
        (text.len() <= MAX_SOURCE_LINE_BYTES).then(|| text.to_owned())
    }

    fn push(&mut self, rule: Rule<'_>, range: Option<Range<usize>>, evidence: String) {
        if self.findings.len() >= MAX_FINDINGS {
            self.omitted = true;
            return;
        }
        let source_context = range
            .as_ref()
            .and_then(|r| self.source.get(r.clone()))
            .map(|s| s.chars().take(240).collect());
        let (line, column, end_line, end_column) = range
            .filter(|range| !range.is_empty() && self.source.get(range.clone()).is_some())
            .map(|range| {
                let (line, column) = self.position(range.start);
                let (end_line, end_column) = self.position(range.end);
                (line, column, end_line, end_column)
            })
            .unwrap_or_default();
        self.findings.push(Finding {
            id: rule.id.into(),
            tool: self.tool.into(),
            path: self.path.into(),
            cwe: rule.cwe.map(str::to_owned),
            severity: rule.severity.into(),
            confidence: rule.confidence.into(),
            category: self.category.into(),
            explanation: rule.explanation.into(),
            remediation: rule.remediation.into(),
            evidence,
            source_context,
            source_line: self.snapshot_line(line),
            line,
            column,
            end_line,
            end_column,
        });
    }

    fn coverage(&mut self, id: &'static str, explanation: &'static str) {
        let index = self.findings.len();
        self.push(
            Rule {
                id,
                cwe: None,
                severity: "info",
                confidence: "high",
                explanation,
                remediation: "Review this file separately if it is in scope.",
            },
            None,
            String::new(),
        );
        if let Some(finding) = self.findings.get_mut(index) {
            finding.category = "coverage".into();
        }
    }

    fn finish(mut self) -> Vec<Finding> {
        if self.omitted {
            self.findings.pop();
            self.coverage(
                "HEL-SCAN-LIMIT",
                "The finding limit for this file was reached. Review coverage is partial.",
            );
        }
        self.findings.sort_by(|first, second| {
            (first.line, first.column, &first.id, &first.evidence).cmp(&(
                second.line,
                second.column,
                &second.id,
                &second.evidence,
            ))
        });
        self.findings.dedup_by(|first, second| first == second);
        self.findings
    }
}
