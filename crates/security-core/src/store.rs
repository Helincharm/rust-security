use crate::Scan;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const SCHEMA_VERSION: i64 = 1;
const CREATE_SCANS: &str = "CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    created_at TEXT NOT NULL,
    files INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    result TEXT NOT NULL
)";
const CHECK_SCAN_COLUMNS: &str =
    "SELECT id, project, created_at, files, findings, result FROM scans LIMIT 0";

#[derive(Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: String,
    pub project: String,
    pub created_at: String,
    pub files: usize,
    pub findings: usize,
    pub warning_count: usize,
}
pub fn try_default_db() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("HELINITY_DB") {
        if path.is_empty() {
            return Err("HELINITY_DB is empty. Set it to a history database path.".into());
        }
        return Ok(PathBuf::from(path));
    }
    directories::ProjectDirs::from("org", "Helinity", "RustSecurity")
        .map(|dirs| dirs.data_local_dir().join("history.sqlite3"))
        .ok_or_else(|| {
            "User data directory unavailable. Set HELINITY_DB to a history database path.".into()
        })
}

fn schema_version(db: &Connection) -> Result<i64, String> {
    db.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())
}

fn check_scan_columns(db: &Connection) -> Result<(), String> {
    db.prepare(CHECK_SCAN_COLUMNS)
        .map(|_| ())
        .map_err(|e| format!("History database schema cannot be read: {e}"))
}

fn require_supported_schema(db: &Connection, version: i64) -> Result<(), String> {
    if version != SCHEMA_VERSION {
        return Err(format!(
            "Unsupported history database schema version {version}. Expected {SCHEMA_VERSION}."
        ));
    }
    check_scan_columns(db)
}

pub struct Store(Connection);
impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        use std::fs;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut options = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                options.mode(0o700);
            }
            options
                .recursive(true)
                .create(parent)
                .map_err(|e| e.to_string())?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| e.to_string())?;
        }
        let mut db = Connection::open(path).map_err(|e| e.to_string())?;
        db.busy_timeout(Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
        db.pragma_update(None, "trusted_schema", false)
            .map_err(|e| e.to_string())?;
        let version = schema_version(&db)?;
        if version == 0 {
            let migration = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| e.to_string())?;
            let version = schema_version(&migration)?;
            if version == 0 {
                migration
                    .execute(CREATE_SCANS, [])
                    .map_err(|e| e.to_string())?;
                check_scan_columns(&migration)?;
                migration
                    .pragma_update(None, "user_version", SCHEMA_VERSION)
                    .map_err(|e| e.to_string())?;
            } else {
                require_supported_schema(&migration, version)?;
            }
            migration.commit().map_err(|e| e.to_string())?;
        } else {
            require_supported_schema(&db, version)?;
        }
        Ok(Self(db))
    }
    pub fn save(&self, scan: &Scan) -> Result<(), String> {
        self.0
            .execute(
                "INSERT INTO scans (id, project, created_at, files, findings, result)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    scan.id,
                    scan.project,
                    scan.created_at,
                    scan.files.len(),
                    scan.findings.len(),
                    serde_json::to_string(scan).map_err(|e| e.to_string())?
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn history(&self) -> Result<Vec<ScanSummary>, String> {
        let mut stmt=self.0.prepare("SELECT id, project, created_at, files,
            CASE WHEN json_type(result,'$.warnings') IS NULL THEN findings - (SELECT count(*) FROM json_each(result,'$.findings') WHERE value->>'category'='coverage') ELSE findings END,
            coalesce(json_array_length(result,'$.warnings'), (SELECT count(*) FROM json_each(result,'$.findings') WHERE value->>'category'='coverage'))
            FROM scans ORDER BY created_at DESC,rowid DESC LIMIT 100").map_err(|e|e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ScanSummary {
                    id: r.get(0)?,
                    project: r.get(1)?,
                    created_at: r.get(2)?,
                    files: r.get(3)?,
                    findings: r.get(4)?,
                    warning_count: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn get(&self, id: &str) -> Result<Scan, String> {
        let raw: String = self
            .0
            .query_row("SELECT result FROM scans WHERE id=?", [id], |r| r.get(0))
            .optional()
            .map_err(|e| format!("Cannot read scan from history: {e}"))?
            .ok_or("Scan not found in history")?;
        let mut scan: Scan = serde_json::from_str(&raw).map_err(|e| format!("Cannot decode saved scan: {e}"))?;
        scan.separate_coverage();
        Ok(scan)
    }
}
