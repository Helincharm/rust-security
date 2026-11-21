# Install Rust Security

Use a trusted checkout in a permanent location and a separate Rust project directory that you want to scan. The installer builds the scanner in the checkout and connects it through local stdio. It does not build or execute the selected Rust project.

## Requirements

Install stable Rust with Cargo and the native linker for your platform, Python 3.11 or newer with venv and pip, and your preferred MCP client. Run the following commands from the scanner checkout. Replace `../my-rust-project` with the path to the directory you want to expose. On Windows, `py -3` can be used in place of `python`.

```sh
python scripts/install_mcp.py --client codex --project "../my-rust-project"
```

For Claude Code, select `--client claude`. Codex stores a client-level MCP connection pinned to that directory. Claude Code registers a local connection for that project. Open a new client session in the selected project and inspect its MCP tools. The server name is `rust-security`. Ask the client to run `analyze_rust_project`, then list findings and retrieve the source location of a finding. Sharing source excerpts is off by default. The local scanner returns evidence locations and analysis warnings separately from security findings.

Use `--client verify` to build the scanner and test stdio without registering a client. Every mode checks a clean fixture, four review markers, a source location and rejection of an out-of-scope path. The selected project's connection is then verified without scanning its files. Use `--client-exe PATH` if your native client executable is outside PATH. Codex reuses a matching registration. Claude Code preserves an existing local registration and reports a duplicate on repeated setup. Review any existing connection in the client before changing its scan root.

The installed scanner and Python environment are in `.rust-security/`. Move or remove the checkout only after disconnecting the server in your client. An initial installation downloads declared dependencies. For an offline installation, populate the Cargo cache and provide a Python interpreter with the pinned SDK using `--offline --mcp-python PATH`. Windows uses the checked-in Python dependency lock. On other systems the SDK version is pinned and pip resolves transitive dependencies.

## Desktop development

The optional UI requires Node.js, npm and [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/). Install the frontend dependencies and build the CLI and the desktop executable into the same target directory. Run from the checkout root.

```sh
npm --prefix apps/desktop ci
npm --prefix apps/desktop run build
cargo build --locked -p helinity --target-dir target
cargo build --locked --manifest-path apps/desktop/src-tauri/Cargo.toml --target-dir target
```

Launch `target/debug/helinity-desktop` (add `.exe` on Windows). For the desktop MCP setup screen, select the Python executable used by the installer. Native build and stdio smoke tests were exercised on Windows. Linux and macOS native launch validation remains open.

## Tests

```sh
cargo test --workspace --locked
python scripts/install_mcp.py --client verify --project fixtures/static
```

The read-only static scan requires no model, API key or container. Optional container-fixture execution has separate isolation requirements. [Runtime security model](SECURITY_MODEL_RUNTIME.md)
