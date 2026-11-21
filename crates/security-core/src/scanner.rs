use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};
pub use static_analysis::Finding;
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_FILE: usize = 256 * 1024;
const MAX_TOTAL: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 10000;
const MAX_FILES: usize = 512;
const MAX_FINDINGS: usize = 4096;
const MAX_DIAGNOSTICS: usize = 128;
const TIME_LIMIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub path: String,
    pub name: Option<String>,
    pub version: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub project: String,
    pub created_at: String,
    pub files: Vec<String>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub warnings: Vec<Finding>,
    pub diagnostics: Vec<String>,
    pub manifests: Vec<Manifest>,
}
impl Scan {
    /// Moves category-"coverage" findings from `self.findings` into
    /// `self.warnings`, keeping the relative order of both groups.
    /// Idempotent. Call it after a fresh scan completes and after a scan is
    /// deserialized from the db.
    pub(crate) fn separate_coverage(&mut self) {
        let (coverage, rest): (Vec<Finding>, Vec<Finding>) =
            std::mem::take(&mut self.findings)
                .into_iter()
                .partition(|f| f.category == "coverage");

        self.findings = rest;
        self.warnings.extend(coverage);
    }
}

fn unsupported_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}
fn safe_regular(file: &cap_std::fs::File) -> Result<bool, String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Ok(metadata.nlink() == 1)
    }
    #[cfg(windows)]
    {
        use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // The live file owns the handle throughout the call. Windows initializes info on success.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err("Could not inspect selected file handle".into());
        }
        Ok(unsafe { info.assume_init() }.nNumberOfLinks == 1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(false)
    }
}
fn relevant(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "rs")
        || matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("Cargo.lock" | "Cargo.toml")
        )
}
fn clean(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
#[derive(Default)]
struct Diagnostics {
    messages: Vec<String>,
    dropped: usize,
}

impl Diagnostics {
    fn push(&mut self, message: String) {
        if self.messages.len() < MAX_DIAGNOSTICS {
            self.messages.push(message);
        } else {
            self.dropped += 1;
        }
    }

    fn finish(mut self, budgets: &[&str]) -> Vec<String> {
        let mut retained = MAX_DIAGNOSTICS - budgets.len();
        if self.dropped > 0 || self.messages.len() > retained {
            retained -= 1;
        }
        if self.messages.len() > retained {
            self.dropped += self.messages.len() - retained;
            self.messages.truncate(retained);
        }
        let mut summary: Vec<_> = budgets.iter().map(|note| (*note).to_owned()).collect();
        if self.dropped > 0 {
            summary.push(format!(
                "{} additional scan diagnostic(s) omitted",
                self.dropped
            ));
        }
        summary.append(&mut self.messages);
        summary
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".into());
    }
    Ok(())
}

/// Scan a developer-selected path. Coverage gaps and exhausted budgets are
/// recorded in the returned scan. Cancellation returns an error and no scan.
/// The time budget is checked between operations, including directory reads.
pub fn scan(
    path: &Path,
    cancel: &AtomicBool,
    progress: impl Fn(usize, &str),
) -> Result<Scan, String> {
    check_cancel(cancel)?;
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot open target: {e}"))?;
    if unsupported_link(&meta) {
        return Err("Choose a regular file or directory, not a link or reparse point".into());
    }
    let abs = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let (base, first) = if meta.is_dir() {
        (abs.clone(), PathBuf::new())
    } else if meta.is_file() && relevant(&abs) {
        (
            abs.parent()
                .ok_or("Missing parent directory")?
                .to_path_buf(),
            PathBuf::from(abs.file_name().ok_or("Missing file name")?),
        )
    } else {
        return Err(
            "Select a Rust source file, Cargo manifest, lockfile or project directory".into(),
        );
    };
    let root = Dir::open_ambient_dir(&base, ambient_authority()).map_err(|e| e.to_string())?;
    scan_from(&root, &abs, first, cancel, progress)
}

/// A directory capability held for the lifetime of one MCP server.
/// Relative requests never reopen or recanonicalize the operator-selected root.
pub struct ProjectScope {
    root: Dir,
    path: PathBuf,
}
impl ProjectScope {
    pub fn open(path: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_dir() || unsupported_link(&meta) {
            return Err("Choose a real project directory".into());
        }
        let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
        let root = match (absolute.parent(), absolute.file_name()) {
            (Some(parent), Some(name)) => {
                let dir = Dir::open_ambient_dir(parent, ambient_authority())
                    .map_err(|e| e.to_string())?;
                let file =
                    cap_primitives::fs::open_dir_nofollow(&dir.into_std_file(), Path::new(name))
                        .map_err(|e| e.to_string())?;
                Dir::from_std_file(file)
            }
            _ => {
                Dir::open_ambient_dir(&absolute, ambient_authority()).map_err(|e| e.to_string())?
            }
        };
        Ok(Self {
            root,
            path: absolute,
        })
    }
    pub fn analyze(&self, relative: &Path, kind: &str) -> Result<Scan, String> {
        use std::path::Component;
        let mut clean = PathBuf::new();
        for component in relative.components() {
            match component {
                Component::CurDir => continue,
                Component::Normal(name)
                    if !name.to_string_lossy().starts_with('.')
                        && !name.to_string_lossy().contains(':') =>
                {
                    clean.push(name);
                    let meta = self
                        .root
                        .symlink_metadata(&clean)
                        .map_err(|_| "Unavailable path within project")?;
                    if meta.file_type().is_symlink() {
                        return Err("Links outside scan policy".into());
                    }
                    #[cfg(windows)]
                    {
                        use cap_std::fs::MetadataExt;
                        if meta.file_attributes() & 0x400 != 0 {
                            return Err("Reparse point outside scan policy".into());
                        }
                    }
                }
                _ => return Err("Path outside project scope".into()),
            }
        }
        let target = if clean.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &clean
        };
        let m = self
            .root
            .symlink_metadata(target)
            .map_err(|_| "Unavailable project target")?;
        let valid = match kind {
            "project" => m.is_dir(),
            "source" => m.is_file() && clean.extension().is_some_and(|e| e == "rs"),
            "dependencies" => m.is_file() && clean.file_name().is_some_and(|n| n == "Cargo.lock"),
            _ => false,
        };
        if !valid {
            return Err("Incorrect target type".into());
        }
        scan_from(
            &self.root,
            &self.path.join(&clean),
            clean,
            &AtomicBool::new(false),
            |_, _| {},
        )
    }
}
fn scan_from(
    root: &Dir,
    abs: &Path,
    first: PathBuf,
    cancel: &AtomicBool,
    progress: impl Fn(usize, &str),
) -> Result<Scan, String> {
    let mut result = Scan {
        id: uuid::Uuid::new_v4().to_string(),
        project: abs.display().to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs()
            .to_string(),
        files: vec![],
        findings: vec![],
        warnings: vec![],
        diagnostics: vec![],
        manifests: vec![],
    };
    let start = Instant::now();
    let mut todo = vec![first];
    let mut entries = 0;
    let mut total = 0;
    let mut seen = HashSet::new();
    let mut diagnostics = Diagnostics::default();
    let mut budgets = Vec::new();
    let mut entry_budget_reached = false;
    'traversal: while let Some(rel) = todo.pop() {
        check_cancel(cancel)?;
        if start.elapsed() >= TIME_LIMIT {
            budgets.push("Scan time budget reached. Coverage is partial.");
            break;
        }
        let local = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &rel
        };
        let sm = match root.symlink_metadata(local) {
            Ok(m) => m,
            Err(e) => {
                diagnostics.push(format!("{}: cannot read entry metadata: {e}", clean(local)));
                continue;
            }
        };
        if sm.file_type().is_symlink() {
            diagnostics.push(format!("{}: symbolic link skipped", clean(local)));
            continue;
        }
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            if sm.file_attributes() & 0x400 != 0 {
                diagnostics.push(format!("{}: reparse point skipped", clean(local)));
                continue;
            }
        }
        if sm.is_dir() {
            if rel.components().count() > 32 {
                diagnostics.push(format!("{}: directory depth limit reached", clean(local)));
                continue;
            }
            if entry_budget_reached {
                continue;
            }
            let dir = match root.open_dir(local) {
                Ok(d) => d,
                Err(e) => {
                    diagnostics.push(format!("{}: cannot open directory: {e}", clean(local)));
                    continue;
                }
            };
            let listing = match dir.entries() {
                Ok(listing) => listing,
                Err(e) => {
                    diagnostics.push(format!("{}: cannot list directory: {e}", clean(local)));
                    continue;
                }
            };
            let mut children = Vec::new();
            for entry in listing {
                check_cancel(cancel)?;
                if start.elapsed() >= TIME_LIMIT {
                    budgets.push("Scan time budget reached. Coverage is partial.");
                    break 'traversal;
                }
                if entries == MAX_ENTRIES {
                    entry_budget_reached = true;
                    budgets.push("Directory entry budget reached. Coverage is partial.");
                    break;
                }
                entries += 1;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        diagnostics.push(format!(
                            "{}: cannot read directory entry: {e}",
                            clean(local)
                        ));
                        continue;
                    }
                };
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.')
                    || matches!(
                        name.to_str(),
                        Some("target" | "node_modules" | "vendor" | "dist")
                    )
                {
                    diagnostics.push(format!(
                        "{}: excluded by scan path policy",
                        clean(&rel.join(name))
                    ));
                    continue;
                }
                children.push(rel.join(name));
            }
            children.sort();
            todo.extend(children.into_iter().rev());
            continue;
        }
        if !relevant(&rel) {
            continue;
        }
        let label = clean(&rel);
        if !sm.is_file() {
            diagnostics.push(format!("{label}: non-regular source entry skipped"));
            continue;
        }
        if sm.len() > MAX_FILE as u64 {
            diagnostics.push(format!("{label}: exceeds 256 KiB per-file limit"));
            continue;
        }
        if result.files.len() >= MAX_FILES {
            budgets.push("Source file count budget reached. Coverage is partial.");
            break;
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NONBLOCK);
        }
        let file = match root.open_with(&rel, &opts) {
            Ok(f) => f,
            Err(e) => {
                diagnostics.push(format!("{label}: cannot open source: {e}"));
                continue;
            }
        };
        match safe_regular(&file) {
            Ok(true) => (),
            Ok(false) => {
                diagnostics.push(format!(
                    "{label}: non-regular or multiply linked file ignored"
                ));
                continue;
            }
            Err(e) => {
                diagnostics.push(format!("{label}: cannot inspect source: {e}"));
                continue;
            }
        }
        let mut buf = Vec::new();
        let read_limit = MAX_FILE.min(MAX_TOTAL - total) + 1;
        let read = file.take(read_limit as u64).read_to_end(&mut buf);
        total += buf.len();
        if total > MAX_TOTAL {
            budgets.push("Scan input byte budget reached. Coverage is partial.");
            break;
        }
        if let Err(e) = read {
            diagnostics.push(format!("{label}: cannot read source: {e}"));
            continue;
        }
        if buf.len() > MAX_FILE {
            diagnostics.push(format!("{label}: source grew beyond limit"));
            continue;
        }
        let Ok(source) = std::str::from_utf8(&buf) else {
            diagnostics.push(format!("{label}: UTF-8 decoding failed"));
            continue;
        };
        progress(result.files.len(), &label);
        check_cancel(cancel)?;
        result.files.push(label.clone());
        let source = source.trim_start_matches('\u{feff}');
        let findings = if rel.ends_with("Cargo.toml") {
            match toml::from_str::<toml::Value>(source) {
                Ok(v) => {
                    let p = v.get("package");
                    result.manifests.push(Manifest {
                        path: label.clone(),
                        name: p.and_then(|p| p.get("name")?.as_str()).map(str::to_owned),
                        version: p
                            .and_then(|p| p.get("version")?.as_str())
                            .map(str::to_owned),
                    });
                }
                Err(_) => diagnostics.push(format!("{label}: invalid Cargo manifest")),
            };
            Vec::new()
        } else if rel.ends_with("Cargo.lock") {
            static_analysis::analyze_lock(&label, source)
        } else {
            static_analysis::analyze_source(&label, source)
        };
        for f in findings {
            if seen.insert((
                f.path.clone(),
                f.id.clone(),
                f.line,
                f.column,
                f.tool.clone(),
            )) {
                if result.findings.len() >= MAX_FINDINGS {
                    budgets.push("Finding count budget reached. Coverage is partial.");
                    break 'traversal;
                }
                result.findings.push(f);
            }
        }
    }
    check_cancel(cancel)?;
    if result.files.is_empty() {
        diagnostics.push("No supported UTF-8 Rust sources or Cargo files were read".into());
    }
    result.diagnostics = diagnostics.finish(&budgets);
    result.separate_coverage();
    Ok(result)
}
