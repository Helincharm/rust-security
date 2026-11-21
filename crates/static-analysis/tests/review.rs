use static_analysis::{analyze_lock, analyze_source};

const MARKERS: &str = include_str!("../../../fixtures/static/review_markers.rs");
const CONTROLS: &str = include_str!("../../../fixtures/static/controls.rs");

#[test]
fn source_patterns_have_locations_and_cwes() {
    let findings = analyze_source("fixtures/static/review_markers.rs", MARKERS);
    let classes: Vec<_> = findings
        .iter()
        .map(|finding| finding.cwe.as_deref())
        .collect();
    assert_eq!(
        classes,
        [
            Some("CWE-89"),
            Some("CWE-78"),
            Some("CWE-22"),
            Some("CWE-20")
        ]
    );
    for (i, finding) in findings.iter().enumerate() {
        assert_eq!(finding.line, (i + 4) as u32);
        assert_eq!(finding.line, finding.end_line);
        assert!(finding.end_column > finding.column && finding.column > 0);
        assert!(!finding.evidence.contains("FIXTURE_"));
    }
}

#[test]
fn recognizes_controls_and_ignores_comments_and_literals() {
    assert!(analyze_source("fixtures/static/controls.rs", CONTROLS).is_empty());
}

#[test]
fn malformed_source_creates_coverage_diagnostic() {
    let findings = analyze_source("src/lib.rs", "fn example( {");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].category, "coverage");
    assert_eq!(findings[0].line, 0);
}

#[test]
fn handles_bom_shebang_and_utf16_columns() {
    let source = "\u{feff}#!/usr/bin/env rust\r\nfn example() { let _ = \"📎\"; let _ = ::std::process::Command::new(std::env::var(\"FIXTURE\").unwrap()); }";
    let findings = analyze_source("src/example.rs", source);
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!((finding.line, finding.column), (2, 38));
    assert_eq!((finding.end_line, finding.end_column), (2, 101));
    assert_eq!(
        finding.source_context.as_deref(),
        Some("::std::process::Command::new(std::env::var(\"FIXTURE\").unwrap())")
    );
}

#[test]
fn commented_inner_attribute_preserves_first_line_code() {
    let source = "\u{feff}#! /* nested /* comment */ here */ [allow(dead_code)] fn example() { let _ = \"📎\"; let _ = std::env::var(\"FIXTURE\").unwrap().as_bytes()[0]; }";
    let findings = analyze_source("src/example.rs", source);
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    let expected_column = source
        .split("std::env")
        .next()
        .unwrap()
        .encode_utf16()
        .count() as u32
        + 1;
    assert_eq!(finding.id, "HEL-RUST-004");
    assert_eq!((finding.line, finding.column), (1, expected_column));
    assert_eq!(
        finding.source_context.as_deref(),
        Some("std::env::var(\"FIXTURE\").unwrap().as_bytes()[0]")
    );
}

#[test]
fn scans_past_independent_match_comparison_guards() {
    let arms = (0..96)
        .map(|i| format!("x if x < {i} => (),\n"))
        .collect::<String>();
    let source = format!(
        "fn example(n: u32) {{ match n {{\n{arms}_ => (),\n}}\nlet _ = std::env::var(\"FIXTURE\").unwrap().as_bytes()[0];\n}}"
    );
    let findings = analyze_source("src/lib.rs", &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-RUST-004");
    assert_eq!(findings[0].line, 100);
}

#[test]
fn top_level_documentation_is_independent_of_expression_depth() {
    let docs = "//! Module documentation.\n".repeat(200) + &"/// Item documentation.\n".repeat(200);
    let source = format!(
        "{docs}fn example() {{ let _ = std::env::var(\"FIXTURE\").unwrap().as_bytes()[0]; }}"
    );
    let findings = analyze_source("src/lib.rs", &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-RUST-004");
    assert_eq!(findings[0].line, 401);
}

#[test]
fn documentation_still_counts_toward_file_token_budget() {
    let source = "//! a\n".repeat(17_000);
    let findings = analyze_source("src/lib.rs", &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-AST-LIMIT");
}

#[test]
fn documentation_does_not_reset_an_ongoing_expression() {
    let terms = "+ #[doc = \"term\"] 1 ".repeat(240);
    let source = format!("const TOTAL: usize = 0 {terms};");
    let findings = analyze_source("src/lib.rs", &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-AST-LIMIT");
}

#[test]
fn excessive_token_nesting_creates_coverage_diagnostic() {
    let source = format!(
        "fn example() {{ let _ = {}true{}; }}",
        "(".repeat(256),
        ")".repeat(256)
    );
    let findings = analyze_source("src/lib.rs", &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-AST-LIMIT");
}

#[test]
fn bounds_ungrouped_parser_recursion() {
    let branches = format!(
        "fn example() {{ if true {{}}{} }}",
        " else if true {}".repeat(256)
    );
    let types = format!(
        "type Example = {}u8{};",
        "Option<Result<u8, ".repeat(256),
        ">>".repeat(256)
    );
    for source in [&branches, &types] {
        let findings = analyze_source("src/lib.rs", source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "HEL-AST-LIMIT");
    }
}
fn package(name: &str, version: &str, source: &str) -> String {
    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"{source}\"\n")
}

#[test]
fn lock_matches_public_registry_and_respects_fixed_ranges_and_gaps() {
    let registry = "registry+https://github.com/rust-lang/crates.io-index";
    let source = [
        "version = 4\n".to_string(),
        package("tower-http", "0.1.2+fixture", registry),
        package("tower-http", "0.1.3", registry),
        package("tower-http", "0.1.9", registry),
        package("tower-http", "0.2.0", registry),
        package("tower-http", "0.2.1", registry),
        package("tower-http", "0.2.0", "registry+https://example.invalid"),
    ]
    .concat();
    let findings = analyze_lock("Cargo.lock", &source);
    assert_eq!(findings.len(), 2);
    assert_eq!((findings[0].line, findings[1].line), (4, 16));
    assert!(findings
        .iter()
        .all(|finding| finding.id == "RUSTSEC-2022-0043"));
}

#[test]
fn malformed_lock_creates_coverage_diagnostic() {
    let findings = analyze_lock("Cargo.lock", "[[package]\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "HEL-LOCK-PARSE");
}

#[test]
fn follows_explicit_imports_and_immutable_value_aliases() {
    let source = r#"
        use std::{env::var as setting, fs::{self as files}, process::Command as Builder};
        use sqlx::query_scalar as query;
        fn inspect(root: &std::path::Path, label: &str) -> Result<(), std::env::VarError> {
            let statement = format!("SELECT {}", label);
            let _ = query(&statement);
            let _ = query(&format!("SELECT {count}", count = 1));
            let result = setting("FIXTURE_PROGRAM");
            let program = result?;
            let _ = Builder::new(&program);
            let path = root.join(program);
            let _ = files::read(path);
            let value = setting("FIXTURE_BYTES").expect("fixture");
            let bytes = value.as_bytes();
            let view = bytes;
            let _ = view[0];
            Ok(())
        }
    "#;
    let findings = analyze_source("src/lib.rs", source);
    let evidence: Vec<_> = findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding.source_context.as_deref()))
        .collect();
    assert_eq!(
        evidence,
        [
            ("HEL-RUST-001", Some("query(&statement)")),
            ("HEL-RUST-002", Some("Builder::new(&program)")),
            ("HEL-RUST-003", Some("files::read(path)")),
            ("HEL-RUST-004", Some("view[0]")),
        ]
    );
}

#[test]
fn length_guards_apply_only_to_proven_byte_indexes_of_the_same_value() {
    let source = r#"
        fn inspect(flag: bool) {
            let text = std::env::var("FIXTURE_TEXT").unwrap();
            let bytes = text.as_bytes();
            let view = bytes;
            if text.len() >= 2 {
                let _ = view[1];
                let _ = view[2];
            }
            if flag || bytes.len() > 2 {
                let _ = bytes[2];
            }
            if 3 <= bytes.len() && bytes[2] == b'x' {
                let _ = view[2];
            }
            if bytes.is_empty() {} else {
                let _ = view[0];
            }
            if text.len() < 3 || flag {
                return;
            }
            let _ = view[2];
            let other = std::env::var("FIXTURE_OTHER").unwrap();
            let _ = other.as_bytes()[2];
            if other.len() != 0 {
                let _ = other.as_bytes()[0];
                let _ = other.as_bytes()[1];
            }
        }
    "#;
    let findings = analyze_source("src/lib.rs", source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        [8, 11, 24, 27]
    );
    assert!(findings.iter().all(|finding| finding.id == "HEL-RUST-004"));
}

#[test]
fn handles_lexical_shadowing_and_module_boundaries() {
    let source = r#"
        use std::process::Command as Builder;
        use sqlx::query as sql;
        mod isolated {
            pub fn sql(_: &str) {}
            fn inspect(label: &str) {
                sql(&format!("SELECT {}", label));
            }
        }
        fn inspect(label: &str) {
            mod std {
                pub mod process {
                    pub struct Command;
                    impl Command {
                        pub fn new(_: String) -> Self { Self }
                    }
                }
            }
            let value = ::std::env::var("FIXTURE_PROGRAM").unwrap();
            let _ = std::process::Command::new(&value);
            let _ = Builder::new(&value);
            let sql = |_statement: &str| ();
            sql(&format!("SELECT {}", label));
        }
        fn macros(label: &str) {
            macro_rules! format { ($($arg:tt)*) => { "SELECT 1" }; }
            sql(format!("SELECT {}", label));
            sql(&::std::format!("SELECT {}", label));
        }
        trait FixtureBuilder {
            fn new(_: &str);
        }
        fn generics<Builder: FixtureBuilder>() {
            let value = std::env::var("FIXTURE_PROGRAM").unwrap();
            Builder::new(&value);
        }
        fn values(flag: bool) {
            let value = std::env::var("FIXTURE_TEXT").unwrap();
            if value.is_empty() { return; }
            if let Some(value) = Some("fixture") {
                let _ = value.as_bytes()[0];
            }
            {
                let value = "fixture";
                let _ = value.as_bytes()[0];
            }
            let _ = value.as_bytes()[0];
            let mut value = "initial";
            if flag { value = "fixture"; }
            let _ = value.as_bytes()[0];
        }
    "#;
    let findings = analyze_source("src/lib.rs", source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.id.as_str(), finding.source_context.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("HEL-RUST-002", Some("Builder::new(&value)")),
            (
                "HEL-RUST-001",
                Some("sql(&::std::format!(\"SELECT {}\", label))")
            ),
        ]
    );
}

#[test]
fn shell_quote_checks_the_predicate_and_unchanged_branch() {
    let source = r#"
fn encode(raw: &[u8]) -> Cow<[u8]> {
    if raw.iter().any(|item| match *item as char {
        '$' | '`' | '|' | '&' | ';' => true,
        _ => false
    }) {
        let mut buf = Vec::new();
        buf.push(b'"');
        buf.extend_from_slice(raw);
        buf.push(b'"');
        buf.into()
    } else { raw.into() }
}
"#;
    let hits = |s: &str| analyze_source("unrelated.rs", s).into_iter()
        .filter(|f| f.id == "HEL-RUST-005").count();
    assert_eq!(hits(source), 1);
    let corrected = source.replace("';' =>", "';' | '{' | '\\u{a0}' =>");
    assert_eq!(hits(&corrected), 0);
    assert_eq!(hits(&source.replace("raw.into()", "escape(raw)")), 0);
    assert_eq!(hits(&source.replace("match *item", "match *other")), 0);
    assert_eq!(hits(&source.replace("_ => false", "_ => true")), 0);
}
