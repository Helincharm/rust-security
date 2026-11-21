// Source-only fixture for the AST scanner.
#[cfg(any())]
fn inspect(root: &std::path::Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = sqlx::query(&format!("SELECT caption FROM labels WHERE caption = {}", label));
    let _ = std::process::Command::new(std::env::var("FIXTURE_PROGRAM")?);
    let _ = std::fs::read(root.join(std::env::var("FIXTURE_NAME")?));
    let _ = std::env::var("FIXTURE_TEXT")?.as_bytes()[0];
    Ok(())
}