use static_analysis::analyze_source;

const DIRECT: &str = r#"
fn collect(folder: &Path, requested: &str) -> Option<PathBuf> {
    let mut target = folder.to_path_buf();
    for part in requested.split('/') {
        if part.starts_with("..") || part.contains('\\') {
            return None;
        }
        target.push(part);
    }
    Some(target)
}"#;

fn count(source: &str) -> usize {
    let observations = analyze_source("arbitrary.rs", source);
    assert!(observations.iter().all(|o| o.category != "coverage"));
    observations
        .iter()
        .filter(|o| o.id == "HEL-RUST-006")
        .count()
}

#[test]
fn tracks_caller_segments_into_the_returned_path() {
    let items = analyze_source("arbitrary.rs", DIRECT);
    let finding = items.iter().find(|o| o.id == "HEL-RUST-006").unwrap();
    assert_eq!(finding.cwe.as_deref(), Some("CWE-22"));
    assert_eq!(finding.line, 8);
    assert_eq!(finding.source_context.as_deref(), Some("target.push(part)"));
    let nested = DIRECT.replace(
        r#"if part.starts_with("..") || part.contains('\\') {
            return None;
        }
        target.push(part);"#,
        r#"if part.starts_with("..") { return None; }
        else if part.contains('\\') { return None; }
        else { target.push(part) }"#,
    );
    assert_ne!(nested, DIRECT);
    assert_eq!(count(&nested), 1);
}

#[test]
fn declines_platform_checked_validated_and_unrelated_appends() {
    for safe in [
        DIRECT.replace(
            "target.push(part);",
            "if cfg!(windows) && part.contains(':') { return None } target.push(part);",
        ),
        DIRECT.replace(
            "target.push(part);",
            "if !is_normal_segment(part) { return None } target.push(part);",
        ),
        DIRECT.replace("requested.split", "validate_path(requested)?.split"),
        DIRECT.replace("target.push(part);", "target.push(validated(part)?);"),
        DIRECT.replace("requested.split", r#""docs/readme".split"#),
        DIRECT.replace("target.push(part);", "different.push(part);"),
        DIRECT.replace("Some(target)", "Some(checked(target)?)"),
    ] {
        assert_eq!(count(&safe), 0, "{safe}");
    }
}
