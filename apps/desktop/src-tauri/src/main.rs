#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

use security_core::{ai, ScanSummary, Store};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::{
    ipc::Channel, webview::NewWindowResponse, AppHandle, State, Url, WebviewWindow,
    WebviewWindowBuilder,
};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct Workspace {
    target: Mutex<Option<PathBuf>>,
    startup_error: Option<String>,
    review: Mutex<()>,
    scan: Arc<Mutex<Option<ScanPhase>>>,
}

enum ScanPhase {
    Running(Arc<AtomicBool>),
    Saving,
}

struct OperationGuard<T>(Arc<Mutex<Option<T>>>);

impl<T> Drop for OperationGuard<T> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = None;
        }
    }
}

#[derive(Clone, Serialize)]
struct Progress {
    files: usize,
    path: String,
}

fn open_store() -> Result<Store, String> {
    Store::open(&security_core::try_default_db()?)
}

async fn worker<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|error| error.to_string())?
}

fn is_rust_input(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("rs")
        || matches!(
            path.file_name().and_then(|value| value.to_str()),
            Some("Cargo.toml" | "Cargo.lock")
        )
}

fn startup_workspace() -> Workspace {
    let mut args = std::env::args_os().skip(1);
    let Some(flag) = args.next() else {
        return Workspace::default();
    };
    let target = (|| {
        if flag != "--open" {
            return Err(
                "Usage: helinity-desktop --open <Rust file or project directory>".to_string(),
            );
        }
        let input = args.next().ok_or("The --open argument requires a path.")?;
        if args.next().is_some() {
            return Err("Use --open with exactly one path.".to_string());
        }
        let path = std::path::absolute(input).map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Choose a regular file or directory for --open.".into());
            }
        }
        if metadata.is_dir() || (metadata.is_file() && is_rust_input(&path)) {
            Ok(path)
        } else {
            Err(
                "Use --open with a Rust source file, Cargo manifest, lockfile, or directory."
                    .into(),
            )
        }
    })();
    match target {
        Ok(path) => Workspace {
            target: Mutex::new(Some(path)),
            ..Workspace::default()
        },
        Err(reason) => Workspace {
            startup_error: Some(reason),
            ..Workspace::default()
        },
    }
}

#[tauri::command]
fn current_target(state: State<'_, Workspace>) -> Result<Option<String>, String> {
    let current = state.target.lock().map_err(|error| error.to_string())?;
    if let Some(path) = current.as_ref() {
        return Ok(Some(path.to_string_lossy().into_owned()));
    }
    if let Some(reason) = &state.startup_error {
        return Err(reason.clone());
    }
    Ok(None)
}

#[tauri::command]
async fn choose_target(
    app: AppHandle,
    state: State<'_, Workspace>,
    folder: bool,
) -> Result<Option<String>, String> {
    let path = worker(move || {
        let dialog = app.dialog().file();
        let selected = if folder {
            dialog
                .set_title("Select a Rust project")
                .blocking_pick_folder()
        } else {
            dialog
                .set_title("Select a Rust source or Cargo file")
                .add_filter("Rust source and Cargo files", &["rs", "toml", "lock"])
                .blocking_pick_file()
        };
        selected
            .map(|path| path.into_path().map_err(|error| error.to_string()))
            .transpose()
    })
    .await?;
    if let Some(path) = path {
        if !folder && !is_rust_input(&path) {
            return Err("Choose a .rs file, Cargo.toml or Cargo.lock.".into());
        }
        let display = path.to_string_lossy().into_owned();
        *state.target.lock().map_err(|error| error.to_string())? = Some(path);
        return Ok(Some(display));
    }
    Ok(None)
}

#[tauri::command]
async fn scan_target(
    state: State<'_, Workspace>,
    progress: Channel<Progress>,
) -> Result<Option<serde_json::Value>, String> {
    let path = state
        .target
        .lock()
        .map_err(|error| error.to_string())?
        .clone()
        .ok_or("Choose a Rust project or source file first.")?;
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.scan.lock().map_err(|error| error.to_string())?;
        if active.is_some() {
            return Err("A scan is already running.".into());
        }
        *active = Some(ScanPhase::Running(cancel.clone()));
    }
    let guard = OperationGuard(state.scan.clone());
    worker(move || {
        let result = security_core::scan(&path, &cancel, |files, path| {
            if files <= 1 || files % 20 == 0 {
                let _ = progress.send(Progress {
                    files,
                    path: path.to_string(),
                });
            }
        });
        let scan = {
            let mut active = guard.0.lock().map_err(|error| error.to_string())?;
            if cancel.load(Ordering::Relaxed) {
                return Ok(None);
            }
            let scan = result?;
            *active = Some(ScanPhase::Saving);
            scan
        };
        open_store()?.save(&scan)?;
        Ok(Some(security_core::json_report(&scan)))
    })
    .await
}

#[tauri::command]
fn cancel_scan(state: State<'_, Workspace>) -> Result<bool, String> {
    if let Some(ScanPhase::Running(active)) = state
        .scan
        .lock()
        .map_err(|error| error.to_string())?
        .as_ref()
    {
        active.store(true, Ordering::Relaxed);
        return Ok(true);
    }
    Ok(false)
}

#[tauri::command]
async fn history() -> Result<Vec<ScanSummary>, String> {
    worker(|| open_store()?.history()).await
}

#[tauri::command]
async fn get_scan(id: String) -> Result<serde_json::Value, String> {
    worker(move || Ok(security_core::json_report(&open_store()?.get(&id)?))).await
}

#[tauri::command]
async fn investigate_scan(scan_id: String, question: String) -> Result<serde_json::Value, String> {
    worker(move || {
        let scan = open_store()?.get(&scan_id)?;
        security_core::review::investigate(&scan, &question)
    })
    .await
}

#[tauri::command]
fn mcp_setup() -> Result<serde_json::Value, String> {
    let app = std::env::current_exe().map_err(|e| e.to_string())?;
    let folder = app.parent().ok_or("Application folder unavailable")?;
    let binary = folder.join(if cfg!(windows) { "helinity.exe" } else { "helinity" });
    if !binary.is_file() { return Err("Install the Helinity CLI alongside the desktop app.".into()); }
    let relative = if cfg!(windows) { ".rust-security/venv/Scripts/python.exe" } else { ".rust-security/venv/bin/python" };
    let python = std::env::var_os("HELINITY_MCP_PYTHON").map(PathBuf::from)
        .or_else(|| folder.ancestors().find(|p| p.join("mcp_server/server.py").is_file() && p.join(relative).is_file()).map(|p| p.join(relative)))
        .filter(|p| p.is_absolute() && p.is_file());
    Ok(serde_json::json!({"command": binary, "python": python}))
}

#[tauri::command]
async fn choose_mcp_root(app: AppHandle) -> Result<Option<String>, String> {
    worker(move || {
        app.dialog().file().set_title("Choose a folder to share with your MCP client")
            .blocking_pick_folder().map(|f| f.into_path().map(|p| p.to_string_lossy().into_owned()).map_err(|e| e.to_string())).transpose()
    }).await
}

#[tauri::command]
async fn export_report(
    app: AppHandle,
    id: String,
    format: String,
) -> Result<Option<String>, String> {
    worker(move || {
        let scan = open_store()?.get(&id)?;
        let (label, extension, report) = match format.as_str() {
            "sarif" => ("SARIF report", "sarif", security_core::sarif(&scan)),
            "json" => ("JSON report", "json", security_core::json_report(&scan)),
            _ => return Err("Choose JSON or SARIF.".into()),
        };
        let Some(file) = app
            .dialog()
            .file()
            .set_title("Export a scan report")
            .set_file_name(format!("helinity-report.{extension}"))
            .add_filter(label, &[extension])
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let path = file.into_path().map_err(|error| error.to_string())?;
        if path.extension().and_then(|value| value.to_str()) != Some(extension) {
            return Err(format!("Choose a .{extension} report filename."));
        }
        let data = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("Choose a new report filename: {error}"))?;
        file.write_all(&data).map_err(|error| error.to_string())?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}

#[tauri::command]
async fn ai_connectivity(window: WebviewWindow, config: ai::Config) -> Result<String, String> {
    worker(move || {
        let preview = ai::connection_preview(&config)?;
        confirm_review(&window, &preview)?;
        ai::check_approved_connection(&config, &preview)
    })
    .await
}

#[tauri::command]
async fn ai_preview(
    config: ai::Config,
    scan_id: String,
    finding_index: usize,
) -> Result<String, String> {
    worker(move || {
        let scan = open_store()?.get(&scan_id)?;
        let finding = scan
            .findings
            .get(finding_index)
            .ok_or("The selected finding is no longer available.")?;
        ai::preview(&config, finding)
    })
    .await
}

#[tauri::command]
async fn ai_review(
    window: WebviewWindow,
    config: ai::Config,
    scan_id: String,
    finding_index: usize,
    approved_preview: String,
) -> Result<String, String> {
    worker(move || {
        let scan = open_store()?.get(&scan_id)?;
        let finding = scan
            .findings
            .get(finding_index)
            .ok_or("The selected finding is no longer available.")?;
        let exact = ai::preview(&config, finding)?;
        if approved_preview != exact {
            return Err("The request changed. Generate a new preview before sending.".into());
        }
        let workspace = tauri::Manager::state::<Workspace>(&window);
        let _active = workspace
            .review
            .try_lock()
            .map_err(|_| "An AI review is already awaiting confirmation or running.")?;
        confirm_review(&window, &exact)?;
        ai::explain(&config, finding, &exact)
    })
    .await
}

#[cfg(windows)]
fn confirm_review(window: &WebviewWindow, exact: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
    };

    let preview: serde_json::Value =
        serde_json::from_str(exact).map_err(|error| error.to_string())?;
    let destination = preview["destination"]
        .as_str()
        .ok_or("Missing request destination.")?;
    let model = preview["payload"]["model"]
        .as_str().or_else(||preview["requested_model"].as_str())
        .ok_or("Missing request model.")?;
    let payload = if preview["method"]=="GET" {
        "GET model listing. No request body or project data. A configured provider credential accompanies the request.".to_owned()
    } else {
        serde_json::to_string(&preview["payload"]).map_err(|error| error.to_string())?
    };
    let monitor = window
        .current_monitor()
        .map_err(|error| error.to_string())?
        .ok_or("Cannot verify space for the native approval dialog.")?;
    let scale = monitor.scale_factor();
    let columns = ((f64::from(monitor.size().width) / scale - 260.0) / 16.0)
        .floor()
        .min(60.0) as usize;
    let lines = ((f64::from(monitor.size().height) / scale - 230.0) / 22.0)
        .floor()
        .min(24.0) as usize;
    if columns < 35 || lines < 12 {
        return Err(
            "The current display is too small to show the complete native approval prompt.".into(),
        );
    }

    let request = format!(
        "Send this request?\n\nDestination: {destination}\nModel: {model}\n\nRequest details:\n{payload}"
    );
    let mut body = String::new();
    let mut rows = 1;
    let mut column = 0;
    for character in request.chars() {
        if character == '\n' {
            body.push(character);
            rows += 1;
            column = 0;
            continue;
        }
        // Escape control and directional formatting characters so evidence cannot disguise the destination
        // or change the reading order of the lossy native rendering.
        let literal = match character {
            '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{00a0}'
            | '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202f}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}' => format!("\\u{{{:x}}}", u32::from(character)),
            _ => character.to_string(),
        };
        let width = literal
            .chars()
            .map(|value| if value.is_ascii() { 1 } else { 2 })
            .sum::<usize>();
        if column + width > columns {
            body.push('\n');
            rows += 1;
            column = 0;
        }
        body.push_str(&literal);
        column += width;
        if rows > lines {
            return Err("This request exceeds the size of the native approval dialog.".into());
        }
    }
    let body: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "Helinity · Confirm AI review"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let hwnd = window.hwnd().map_err(|error| error.to_string())?;
    // The UTF-16 buffers remain live and null-terminated for the duration of MessageBoxW.
    let selection = unsafe {
        MessageBoxW(
            hwnd.0.cast(),
            body.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
        )
    };
    if selection == IDYES {
        Ok(())
    } else {
        Err("AI review was cancelled in the native dialog.".into())
    }
}

#[cfg(not(windows))]
fn confirm_review(_window: &WebviewWindow, _exact: &str) -> Result<(), String> {
    Err("The native AI approval dialog is available on Windows.".into())
}

fn allow_navigation(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    #[cfg(not(feature = "custom-protocol"))]
    return url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(1420);
    #[cfg(all(feature = "custom-protocol", windows))]
    return url.scheme() == "http"
        && url.host_str() == Some("tauri.localhost")
        && url.port().is_none();
    #[cfg(all(feature = "custom-protocol", not(windows)))]
    return url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none();
}

#[tauri::command]
async fn runtime_info(request: bool) -> Result<serde_json::Value, String> {
    worker(move || {
        Ok(if request {
            runtime_analysis::request()
        } else {
            runtime_analysis::status()
        })
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(startup_workspace())
        .setup(|app| {
            let config = &app.config().app.windows[0];
            WebviewWindowBuilder::from_config(app, config)?
                .on_navigation(allow_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            current_target,
            choose_target,
            scan_target,
            cancel_scan,
            history,
            get_scan,
            investigate_scan,
            mcp_setup,
            choose_mcp_root,
            export_report,
            ai_connectivity,
            ai_preview,
            ai_review,
            runtime_info,
        ])
        .run(tauri::generate_context!())
        .expect("could not launch Helinity desktop");
}
