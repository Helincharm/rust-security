use security_core::{ai, json_report, sarif, scan, Finding, Scan, Store};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

fn observation() -> Finding {
    Finding {
        source_context: None,
        source_line: None,
        id: "HEL-TEST-001".into(),
        tool: "test-review".into(),
        path: "src/café #1.rs".into(),
        cwe: None,
        severity: "medium".into(),
        confidence: "high".into(),
        category: "static".into(),
        explanation: "The fixture contains an unresolved type name.".into(),
        remediation: "Check the spelling of the type name.".into(),
        evidence: "The identifier is ExampleType.".into(),
        line: 2,
        column: 4,
        end_line: 2,
        end_column: 15,
    }
}

#[test]
fn history_reopens_with_exact_evidence_and_sarif_coordinates() {
    let workspace = tempfile::tempdir().unwrap();
    let database = workspace.path().join("history").join("scans.sqlite3");
    let located = observation();
    let mut unlocated = observation();
    unlocated.line = 0;
    unlocated.column = 0;
    unlocated.end_line = 0;
    unlocated.end_column = 0;
    let recorded = Scan {
        id: "review-1".into(),
        project: workspace.path().display().to_string(),
        created_at: "1763740000".into(),
        files: vec![located.path.clone()],
        findings: vec![located.clone(), unlocated],
        warnings: vec![],
        diagnostics: vec!["Fixture coverage message".into()],
        manifests: vec![],
    };
    let store = Store::open(&database).unwrap();
    store.save(&recorded).unwrap();
    assert!(store.save(&recorded).is_err());
    drop(store);

    let reopened = Store::open(&database).unwrap();
    let history = reopened.history().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, recorded.id);
    assert_eq!(history[0].files, 1);
    assert_eq!(history[0].findings, 2);
    assert_eq!(
        reopened.get("missing").err().as_deref(),
        Some("Scan not found in history")
    );
    let loaded = reopened.get(&recorded.id).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        serde_json::to_value(&recorded).unwrap()
    );
    let exported = json_report(&loaded);
    assert_eq!(exported["schema_version"], 1);
    assert_eq!(exported["findings"][0]["finding_id"], "review-1:0");
    assert_eq!(exported["findings"][1]["finding_id"], "review-1:1");
    assert_eq!(exported["findings"][0]["scan_id"], recorded.id);
    assert_eq!(
        exported["findings"][0]["observed_at_unix"],
        recorded.created_at
    );
    assert_eq!(
        exported["findings"][0]["verification_status"],
        "unverified_static_observation"
    );
    assert_eq!(exported["findings"][0]["evidence"], located.evidence);

    let report = sarif(&loaded);
    let run = &report["runs"][0];
    assert_eq!(report["version"], "2.1.0");
    assert_eq!(run["columnKind"], "utf16CodeUnits");
    let first = &run["results"][0];
    assert_eq!(first["properties"]["evidence"], located.evidence);
    assert_eq!(first["properties"]["analyzer"], located.tool);
    let physical = &first["locations"][0]["physicalLocation"];
    assert_eq!(
        physical["artifactLocation"]["uri"],
        "src/caf%C3%A9%20%231.rs"
    );
    assert_eq!(
        physical["region"],
        json!({"startLine": 2, "startColumn": 4, "endLine": 2, "endColumn": 15})
    );
    assert!(run["results"][1]["locations"][0]["physicalLocation"]
        .get("region")
        .is_none());
}

#[test]
fn history_migrates_unversioned_rows_and_rejects_future_schema() {
    let workspace = tempfile::tempdir().unwrap();
    let database = workspace.path().join("legacy.sqlite3");
    let db = rusqlite::Connection::open(&database).unwrap();
    db.execute_batch(
        "CREATE TABLE scans (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, created_at TEXT NOT NULL,
            files INTEGER NOT NULL, findings INTEGER NOT NULL, result TEXT NOT NULL,
            reserved TEXT
        )",
    )
    .unwrap();
    let legacy = json!({
        "id": "legacy", "project": "fixture", "created_at": "1763740000",
        "files": [], "findings": [], "diagnostics": [], "manifests": []
    });
    db.execute(
        "INSERT INTO scans (id, project, created_at, files, findings, result)
         VALUES ('legacy', 'fixture', '1763740000', 0, 0, ?1)",
        [legacy.to_string()],
    )
    .unwrap();
    drop(db);

    let store = Store::open(&database).unwrap();
    let mut loaded = store.get("legacy").unwrap();
    assert!(loaded.warnings.is_empty());
    assert_eq!(loaded.id, legacy["id"]);
    loaded.id = "new-row".into();
    store.save(&loaded).unwrap();
    assert_eq!(store.history().unwrap().len(), 2);
    drop(store);

    let db = rusqlite::Connection::open(&database).unwrap();
    let version: u32 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
    db.pragma_update(None, "user_version", 99).unwrap();
    assert_eq!(
        Store::open(&database).err().as_deref(),
        Some("Unsupported history database schema version 99. Expected 1.")
    );
    let version: u32 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 99);
}

#[test]
fn scanner_stops_after_cancellation_and_keeps_relative_source_paths() {
    let workspace = tempfile::tempdir().unwrap();
    for name in ["a.rs", "b.rs"] {
        fs::write(
            workspace.path().join(name),
            "fn arithmetic() -> u32 { 2 + 2 }",
        )
        .unwrap();
    }
    for excluded in [".hidden", "target"] {
        let directory = workspace.path().join(excluded);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("ignored.rs"), "fn ignored() {}").unwrap();
    }
    let cancel = AtomicBool::new(false);
    let visited = RefCell::new(Vec::new());
    let stopped = scan(workspace.path(), &cancel, |_, path| {
        visited.borrow_mut().push(path.to_owned());
        cancel.store(true, Ordering::Relaxed);
    });
    assert_eq!(stopped.err().as_deref(), Some("scan cancelled"));
    assert_eq!(visited.into_inner(), ["a.rs"]);

    cancel.store(false, Ordering::Relaxed);
    let finished = scan(workspace.path(), &cancel, |_, _| {}).unwrap();
    assert_eq!(finished.files, ["a.rs", "b.rs"]);
    assert!(finished.findings.is_empty());
    for excluded in [".hidden", "target"] {
        assert!(finished
            .diagnostics
            .iter()
            .any(|message| { message == &format!("{excluded}: excluded by scan path policy") }));
    }
}

#[test]
fn scanner_reports_omitted_diagnostics_and_returns_partial_results_at_the_file_budget() {
    let workspace = tempfile::tempdir().unwrap();
    for index in 0..130 {
        fs::write(workspace.path().join(format!(".excluded-{index:03}")), "").unwrap();
    }
    for index in 0..513 {
        fs::write(workspace.path().join(format!("source-{index:03}.rs")), "").unwrap();
    }
    let scanned = scan(workspace.path(), &AtomicBool::new(false), |_, _| {}).unwrap();
    assert_eq!(scanned.files.len(), 512);
    assert_eq!(
        scanned.files.first().map(String::as_str),
        Some("source-000.rs")
    );
    assert_eq!(
        scanned.files.last().map(String::as_str),
        Some("source-511.rs")
    );
    assert_eq!(scanned.diagnostics.len(), 128);
    assert_eq!(
        scanned.diagnostics[0],
        "Source file count budget reached. Coverage is partial."
    );
    assert_eq!(
        scanned.diagnostics[1],
        "4 additional scan diagnostic(s) omitted"
    );
}

#[test]
fn scanner_preserves_a_harmless_parser_coverage_observation() {
    let workspace = tempfile::tempdir().unwrap();
    let source = workspace.path().join("incomplete.rs");
    fs::write(&source, "fn arithmetic( {").unwrap();
    let scanned = scan(&source, &AtomicBool::new(false), |_, _| {}).unwrap();

    assert_eq!(scanned.files, ["incomplete.rs"]);
    assert!(scanned.findings.is_empty());
    assert_eq!(scanned.warnings.len(), 1);
    let coverage = &scanned.warnings[0];
    assert_eq!(coverage.id, "HEL-AST-PARSE");
    assert_eq!(coverage.path, "incomplete.rs");
    assert_eq!(coverage.category, "coverage");
    assert_eq!(coverage.cwe, None);
    assert_eq!((coverage.line, coverage.column), (0, 0));
}

#[test]
fn scanner_reports_skipped_encoding_and_size_without_discarding_other_files() {
    let workspace = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("bad_encoding.rs"), [0xff]).unwrap();
    fs::write(
        workspace.path().join("oversize.rs"),
        vec![b' '; 256 * 1024 + 1],
    )
    .unwrap();
    fs::write(workspace.path().join("valid.rs"), "fn valid() {}").unwrap();

    let scanned = scan(workspace.path(), &AtomicBool::new(false), |_, _| {}).unwrap();
    assert_eq!(scanned.files, ["valid.rs"]);
    assert_eq!(
        scanned.diagnostics,
        [
            "bad_encoding.rs: UTF-8 decoding failed",
            "oversize.rs: exceeds 256 KiB per-file limit",
        ]
    );
}

#[cfg(any(unix, windows))]
#[test]
fn scanner_ignores_multiply_linked_source_files() {
    let workspace = tempfile::tempdir().unwrap();
    let original = workspace.path().join("original.rs");
    let alias = workspace.path().join("alias.rs");
    let ordinary = workspace.path().join("ordinary.rs");
    fs::write(&original, "fn arithmetic() -> u32 { 2 + 2 }").unwrap();
    fs::write(&ordinary, "fn arithmetic() -> u32 { 3 + 3 }").unwrap();
    match fs::hard_link(&original, &alias) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => return,
        Err(error) => panic!("could not create temporary fixture link: {error}"),
    }

    let scanned = scan(workspace.path(), &AtomicBool::new(false), |_, _| {}).unwrap();
    assert_eq!(scanned.files, ["ordinary.rs"]);
    for label in ["alias.rs", "original.rs"] {
        assert!(scanned.diagnostics.iter().any(|message| {
            message.starts_with(label) && message.contains("multiply linked file ignored")
        }));
    }
}

#[test]
fn compatible_connectivity_and_consented_review_use_the_previewed_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = ai::Config {
        provider: "compatible".into(),
        model: "fixture-review:local".into(),
        endpoint: format!("http://{}", listener.local_addr().unwrap()),
    };
    let finding = observation();
    let preview = ai::preview(&config, &finding).unwrap();
    let expected: Value = serde_json::from_str(&preview).unwrap();
    assert_eq!(
        expected["destination"],
        format!("{}/chat/completions", config.endpoint)
    );

    assert_eq!(expected["payload"]["model"], config.model);
    let content = expected["payload"]["messages"][1]["content"]
        .as_str()
        .unwrap();
    let projected: Value = serde_json::from_str(content).unwrap();
    assert_eq!(projected["evidence"], finding.evidence);
    assert!(projected.get("path").is_none());
    assert_no_request(&listener);

    let mut changed = finding.clone();
    changed.evidence.push_str(" Additional context.");
    assert!(ai::explain(&config, &changed, &preview)
        .unwrap_err()
        .contains("must be approved"));
    let mut changed_model = config.clone();
    changed_model.model = "different-model".into();
    assert!(ai::explain(&changed_model, &finding, &preview)
        .unwrap_err()
        .contains("must be approved"));
    assert_no_request(&listener);

    let server = thread::spawn(move || {
        let tags_stream = accept(&listener);
        let tags = read_request(&tags_stream);
        assert_eq!(tags.0, "GET /models HTTP/1.1");
        respond(
            tags_stream,
            json!({"data": [{"id": "fixture-review:local"}]}),
        );

        let chat_stream = accept(&listener);
        let chat = read_request(&chat_stream);
        assert_eq!(chat.0, "POST /chat/completions HTTP/1.1");
        assert_eq!(
            serde_json::from_slice::<Value>(&chat.1).unwrap(),
            expected["payload"]
        );
        respond(
            chat_stream,
            json!({"choices":[{"message": {"content": "Check the identifier spelling."}}]}),
        );
    });
    ai::check_approved_connection(&config, &ai::connection_preview(&config).unwrap()).unwrap();
    let explanation = ai::explain(&config, &finding, &preview).unwrap();
    assert_eq!(explanation, "Check the identifier spelling.");
    server.join().unwrap();
}

#[test]
fn alternative_providers_preview_their_expected_routes_without_connecting() {
    for (provider, endpoint, route) in [
        ("openai", "https://api.openai.com/v1", "chat/completions"),
        ("anthropic", "https://api.anthropic.com/v1", "messages"),
        (
            "compatible",
            "https://review.invalid/api/v1",
            "chat/completions",
        ),
    ] {
        let config = ai::Config {
            provider: provider.into(),
            model: "fixture-model".into(),
            endpoint: endpoint.into(),
        };
        let request = ai::preview(&config, &observation()).unwrap();
        let preview: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(preview["destination"], format!("{endpoint}/{route}"));
        assert_eq!(preview["payload"]["max_tokens"], 650);
        let payload = &preview["payload"];
        if provider == "anthropic" {
            assert!(payload["system"].is_string());
            assert_eq!(payload["messages"][0]["role"], "user");
        } else {
            assert_eq!(payload["messages"][0]["role"], "system");
            assert_eq!(payload["messages"][1]["role"], "user");
        }
        assert!(ai::check_approved_connection(&config, "unapproved").is_err());
    }
}

fn assert_no_request(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("mock provider did not accept a connection: {error}"),
        }
    }
}

fn read_request(stream: &TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    assert_ne!(reader.read_line(&mut request).unwrap(), 0);
    let mut length = 0;
    loop {
        let mut header = String::new();
        assert_ne!(reader.read_line(&mut header).unwrap(), 0);
        if header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                length = value.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    (request.trim_end().into(), body)
}

fn respond(mut stream: TcpStream, response: Value) {
    let body = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}

#[test]
fn hosted_connectivity_is_a_previewed_get_without_finding_data() {
    for (provider, endpoint) in [
        ("openai", "https://api.openai.com/v1"),
        ("anthropic", "https://api.anthropic.com/v1"),
    ] {
        let config = security_core::ai::Config {
            provider: provider.to_owned(),
            model: "test-only".to_owned(),
            endpoint: endpoint.to_owned(),
        };
        let body = security_core::ai::connection_preview(&config).unwrap();
        let preview: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(preview["method"], "GET");
        assert_eq!(preview["project_data_sent"], false);
        assert_eq!(preview["destination"], format!("{endpoint}/models"));
        assert!(security_core::ai::check_approved_connection(&config, "changed").is_err());
    }
}
