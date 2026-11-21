use clap::{Args, Parser, Subcommand, ValueEnum};
use security_core::{ai, sarif, try_default_db, Scan, Store};
use serde_json::{json, Value};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
#[derive(Parser)]
#[command(version, about = "Local evidence-based review of Rust sources")]
struct App {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Read source and Cargo metadata without building or executing the target.
    Scan {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    History,
    Compare {
        before: String,
        after: String,
    },
    Review {
        scan: String,
        question: String,
    },
    Findings {
        #[arg(long)]
        scan: Option<String>,
    },
    Report {
        #[arg(long)]
        scan: Option<String>,
        #[arg(long, value_enum, default_value = "sarif")]
        format: Format,
    },
    /// Serve only relative paths beneath an explicitly selected directory over stdio.
    Mcp {
        #[arg(long)]
        root: PathBuf,
    },
    #[command(hide = true)]
    ScopedWorker {
        #[arg(long)]
        root: PathBuf,
    },
    Doctor,
    Runtime {
        #[command(subcommand)]
        operation: Runtime,
    },
    /// Preview the exact outgoing evidence and optionally authorize in a terminal.
    Explain {
        #[command(flatten)]
        provider: Provider,
        #[arg(long)]
        scan: String,
        #[arg(long)]
        index: usize,
        #[arg(long)]
        send: bool,
    },
    /// Save an endpoint-specific credential to the OS credential store.
    AiKey {
        #[command(flatten)]
        provider: Provider,
    },
    /// Run the optional local experimental CodeT5 classifier on one Rust file.
    Ml {
        #[arg(long)]
        model_dir: PathBuf,
        file: PathBuf,
    },
}
#[derive(Args)]
struct Provider {
    #[arg(long)]
    provider: String,
    #[arg(long)]
    model: String,
    #[arg(long)]
    endpoint: String,
}
impl From<Provider> for ai::Config {
    fn from(p: Provider) -> Self {
        Self {
            model: p.model,
            provider: p.provider,
            endpoint: p.endpoint,
        }
    }
}
#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Sarif,
}
#[derive(Subcommand)]
enum Runtime {
    Status,
    Request,
    /// Run the fixed arithmetic fixture after fresh terminal confirmation.
    RunFixture,
}
fn project() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if parent.join("mcp_server/server.py").is_file()
                && parent.join("experiments/checkpoints.json").is_file()
            {
                return parent.to_owned();
            }
            // Development executables live under [ .work/ ]target/{debug,release}.
            if let Some(target) = parent.parent().filter(|p| p.ends_with("target")) {
                if let Some(mut root) = target.parent() {
                    if root.ends_with(".work") {
                        if let Some(ancestor) = root.parent() {
                            root = ancestor;
                        }
                    }
                    if root.join("crates/security-cli/Cargo.toml").is_file()
                        && root.join("mcp_server/server.py").is_file()
                    {
                        return root.to_owned();
                    }
                }
            }
            return parent.to_owned();
        }
    }
    PathBuf::new()
}
fn output(v: &impl serde::Serialize) -> Result<(), String> {
    serde_json::to_writer_pretty(io::stdout().lock(), v).map_err(|e| e.to_string())?;
    println!();
    Ok(())
}
fn db() -> Result<Store, String> {
    Store::open(&try_default_db()?)
}
fn lookup(id: Option<String>) -> Result<Scan, String> {
    let store = db()?;
    let id = match id {
        Some(id) => id,
        None => {
            store
                .history()?
                .into_iter()
                .next()
                .ok_or("No saved scans")?
                .id
        }
    };
    store.get(&id)
}
fn confirm(text: &str) -> Result<bool, String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err("An interactive local terminal is required".into());
    }
    eprint!("Type {text} to approve: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut s = String::new();
    io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
    Ok(s.trim() == text)
}
fn python(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            project().join(if cfg!(windows) {
                ".tools/py/Scripts/python.exe"
            } else {
                ".tools/py/bin/python"
            })
        })
}
fn invoke_sidecar(var: &str, script: &str, args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let exe = python(var);
    if !exe.is_absolute() || !exe.is_file() {
        return Err(format!(
            "Configure {var} with the absolute path of a trusted Python environment"
        ));
    }
    let ok = Command::new(exe)
        .arg("-I")
        .arg("-B")
        .arg(project().join(script))
        .args(args)
        .status()
        .map_err(|e| e.to_string())?;
    if ok.success() {
        Ok(())
    } else {
        Err("Local adapter exited unsuccessfully".into())
    }
}
fn findings(data: &Scan) -> Result<(), String> {
    println!(
        "{} files · {} observations · scan {}",
        data.files.len(),
        data.findings.len(),
        data.id
    );
    for f in &data.findings {
        println!(
            "{}  {:?}:{}:{}  {}  {:?}",
            f.id, f.path, f.line, f.column, f.category, f.explanation
        );
    }
    for w in &data.warnings {
        eprintln!("Analysis warning [{}] {:?}: {}", w.id, w.path, w.explanation);
    }
    for d in &data.diagnostics {
        eprintln!("Diagnostic: {d:?}");
    }
    Ok(())
}
fn doctor() -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),"source":"syntax-only","database":try_default_db().ok(),"ai":"optional; explicit per-request consent",
        "runtime":runtime_analysis::status(),"cargo_tools":{"metadata":"offline manifest parser available; Cargo invocation disabled on selected projects",
        "check":"requires isolated build; disabled","clippy":"requires isolated build; disabled","audit":"bundled limited snapshot used; external cargo-audit not invoked","deny":"not connected"},
        "mcp_interpreter_present":python("HELINITY_MCP_PYTHON").is_file()})
}
// Use a closed vocabulary so a filename, parser message or future rule cannot
// become an output key in a source-redacted MCP response.
fn coverage_summary(scan: &Scan) -> Value {
    use std::collections::BTreeMap;

    let mut warnings = BTreeMap::new();
    for warning in &scan.warnings {
        let category = match warning.id.as_str() {
            "HEL-AST-LIMIT" => "ast_parser_limit",
            "HEL-AST-PARSE" => "ast_parse_error",
            "HEL-AST-UNAVAILABLE" => "ast_parser_unavailable",
            "HEL-LOCK-LIMIT" => "lockfile_limit",
            "HEL-LOCK-PARSE" => "lockfile_parse_error",
            "HEL-LOCK-INDEX" => "advisory_index_unavailable",
            "HEL-LOCK-VERSION" => "lockfile_version_unchecked",
            "HEL-SCAN-LIMIT" => "file_finding_limit",
            _ => "other_warning",
        };
        *warnings.entry(category).or_insert(0usize) += 1;
    }
    let mut diagnostics = BTreeMap::new();
    let mut omitted_diagnostics = 0usize;
    for message in &scan.diagnostics {
        let omitted = message
            .strip_suffix(" additional scan diagnostic(s) omitted")
            .and_then(|count| count.parse::<usize>().ok());
        let category = if let Some(count) = omitted {
            omitted_diagnostics += count;
            "omission_notice"
        } else if message.ends_with(": excluded by scan path policy") {
            "path_policy_exclusion"
        } else if message.ends_with(" budget reached. Coverage is partial.") {
            "scan_budget_reached"
        } else if message.ends_with(": invalid Cargo manifest") {
            "invalid_cargo_manifest"
        } else if message == "No supported UTF-8 Rust sources or Cargo files were read" {
            "no_supported_inputs_read"
        } else {
            "other_diagnostic"
        };
        *diagnostics.entry(category).or_insert(0usize) += 1;
    }
    json!({"warning_categories": warnings, "diagnostic_categories": diagnostics,
           "omitted_diagnostics": omitted_diagnostics})
}

fn worker(root: &Path) -> Result<(), String> {
    use std::io::{BufRead, Read};
    let scope = security_core::ProjectScope::open(root)?;
    let store = db()?;
    let mut out = io::stdout().lock();
    writeln!(out, "ready")
        .and_then(|_| out.flush())
        .map_err(|e| e.to_string())?;
    let mut input = io::stdin().lock();
    loop {
        let mut line = Vec::new();
        if (&mut input)
            .take(8193)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            return Ok(());
        }
        if line.len() > 8192 {
            return Err("Oversized worker request".into());
        }
        let response=(||->Result<Value,String>{
            let q:Value=serde_json::from_slice(&line).map_err(|_|"Invalid request")?;
            let scan=scope.analyze(Path::new(q["path"].as_str().ok_or("Missing path")?),q["kind"].as_str().ok_or("Missing kind")?)?;
            store.save(&scan).map_err(|_|"storage_unavailable")?;
            let diagnostics: Vec<String> = scan.diagnostics.iter().take(32).map(|s| s.chars().take(160).collect()).collect();
            Ok(json!({"scan_id":scan.id,"files":scan.files.len(),"findings":scan.findings.len(),"warning_count":scan.warnings.len(),"diagnostics":diagnostics,"diagnostic_count":scan.diagnostics.len(),"coverage":coverage_summary(&scan)}))
        })().unwrap_or_else(|err|json!({"error":if err=="storage_unavailable" {"Local scan storage unavailable"} else {"Invalid, unavailable or over-budget scoped analysis"}}));
        writeln!(out, "{}", response)
            .and_then(|_| out.flush())
            .map_err(|e| e.to_string())?;
    }
}
fn run() -> Result<(), String> {
    match App::parse().command {
        Action::Scan { path, json } => {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))
                .map_err(|e| e.to_string())?;
            let result = security_core::scan(&path, &stop, |n, p| {
                if !json && io::stderr().is_terminal() {
                    eprintln!("Reading {}: {p:?}", n + 1)
                }
            })?;
            db()?.save(&result)?;
            if json {
                output(&security_core::json_report(&result))
            } else {
                findings(&result)
            }
        }
        Action::Compare { before, after } => output(&security_core::review::compare(
            &lookup(Some(before))?,
            &lookup(Some(after))?,
        )?),
        Action::Review { scan, question } => output(&security_core::review::investigate(
            &lookup(Some(scan))?,
            &question,
        )?),
        Action::History => output(&db()?.history()?),
        Action::Findings { scan } => findings(&lookup(scan)?),
        Action::Report { scan, format } => {
            let scan = lookup(scan)?;
            match format {
                Format::Json => output(&security_core::json_report(&scan)),
                Format::Sarif => output(&sarif(&scan)),
            }
        }
        Action::Doctor => output(&doctor()),
        Action::ScopedWorker { root } => worker(&root),
        Action::Mcp { root } => {
            if std::fs::symlink_metadata(&root)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("Choose a directory, not a link".into());
            }
            let root = std::path::absolute(&root).map_err(|e| e.to_string())?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            invoke_sidecar(
                "HELINITY_MCP_PYTHON",
                "mcp_server/server.py",
                &[
                    "--root".as_ref(),
                    root.as_os_str(),
                    "--binary".as_ref(),
                    exe.as_os_str(),
                ],
            )
        }
        Action::Runtime { operation } => match operation {
            Runtime::Status => output(&runtime_analysis::status()),
            Runtime::Request => output(&runtime_analysis::request()),
            Runtime::RunFixture => output(&runtime_analysis::run_fixture_in_terminal()?),
        },
        Action::Explain {
            provider,
            scan,
            index,
            send,
        } => {
            let config = provider.into();
            let data = lookup(Some(scan))?;
            let f = data
                .findings
                .get(index)
                .ok_or("Finding index outside scan")?;
            let preview = ai::preview(&config, f)?;
            println!("{preview}");
            if send && confirm("SEND EVIDENCE")? {
                output(
                    &json!({"source":"unverified AI explanation","text":ai::explain(&config,f,&preview)?}),
                )
            } else {
                Ok(())
            }
        }
        Action::AiKey { provider } => {
            if !io::stdin().is_terminal() {
                return Err("Use an interactive terminal".into());
            }
            let config = provider.into();
            let key = rpassword::prompt_password("Provider credential (hidden): ")
                .map_err(|e| e.to_string())?;
            ai::store_key(&config, &key)
        }
        Action::Ml { model_dir, file } => {
            let model = model_dir.canonicalize().map_err(|e| e.to_string())?;
            let file = file.canonicalize().map_err(|e| e.to_string())?;
            invoke_sidecar(
                "HELINITY_ML_PYTHON",
                "experiments/codet5.py",
                &[model.as_os_str(), file.as_os_str()],
            )
        }
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Helinity: {e:?}");
            if e == "scan cancelled" {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
