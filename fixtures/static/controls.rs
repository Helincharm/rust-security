// Source-only fixture with checked input and fixed interfaces.
#[cfg(any())]
fn inspect(root: &std::path::Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = sqlx::query("SELECT caption FROM labels WHERE caption = ?").bind(label);
    let _ = std::process::Command::new("fixture-program").arg(label);
    let _ = std::fs::read(root.join("fixture.txt"));
    let value = std::env::var("FIXTURE_TEXT")?;
    let _ = value.as_bytes().first().ok_or("Fixture text is empty")?;
    let _ = sqlx::query(&format!("SELECT {}", 1));
    // std::process::Command::new(std::env::var("FIXTURE_PROGRAM")?);
    let _ = "std::fs::read(root.join(std::env::var(...)?))";
    Ok(())
}