# Helinity architecture

Helinity reviews Rust source and Cargo files selected by a developer. The CLI, Tauri desktop app and local MCP server share the same Rust scanner and finding format. Analysis reads text and parses it in process. The runtime fixture, experimental classifier and AI explanations each have a separate entry point.

## Static analysis and scan boundaries

`crates/security-core` owns file traversal, resource limits, cancellation, persistence and report export. It passes UTF-8 `.rs` and `Cargo.lock` text to `crates/static-analysis`. That crate uses `syn` for local expression patterns and a bundled advisory snapshot for offline lockfile matching. The core uses a TOML parser for `Cargo.toml` package summaries. See [Tool adapters](TOOL_ADAPTERS.md) for match semantics and coverage.

The scanner opens a directory capability at the selected root, then traverses relative paths. It skips symlinks, Windows reparse points, multiply linked files, dot-prefixed directory entries and common generated or vendored directories. A scan can visit up to 10,000 directory entries, read 512 supported files and 16 MiB of input, and retain 4,096 findings. File reads have a 256 KiB per-file cap. Traversal also has a depth limit and a cooperative 60-second time budget. The scanner checks for cancellation between traversal steps and before returning a complete result. The CLI uses Ctrl+C and the desktop bridges progress through a Tauri channel while a blocking worker performs the scan.

Unreadable entries, oversize files, unsupported encodings and other recoverable coverage gaps can leave a diagnostic on an otherwise completed scan. Whole-scan resource exhaustion commits bounded partial results with diagnostic notices. Explicit cancellation ends the scan before persistence. A completed scan with zero observations can still contain diagnostics. Static adapters are limited to source and metadata parsing.

## History and reports

The CLI and desktop open a local SQLite database in the application data directory. Operators can set `HELINITY_DB` to choose a different path. A successful scan is inserted as one row with summary fields and the complete scan. The history query returns at most 100 rows. Saved rows keep the finding order used by report and explanation indexes. JSON exports add the schema version, a scan-scoped finding ID, the observation timestamp, severity source and verification status. Treat the database and exports as local review data. The stored record and local JSON exports include the selected project path and evidence.

`security-core` also exports SARIF 2.1.0. Artifact URIs are percent-encoded relative source paths. Known regions use one-based UTF-16 columns and exclusive end coordinates. A finding with no measured location leaves out its region. SARIF properties carry analyzer identity, review priority, confidence, evidence and guidance. Findings and explanations remain subject to human review. The desktop uses a native save dialog for exports. The CLI writes reports to stdout.

## Desktop and MCP entry points

The desktop accepts target selections from a native picker and hands the active scan to the Rust backend. The Tauri frontend renders structured results and prompts for consent before requesting an AI explanation. Scans, history queries, report exports and network requests run off the UI thread.

The MCP server runs over local stdio. A long-lived Rust worker opens the operator-selected directory at startup and holds that capability for the life of the session. It accepts relative file, project and dependency targets and checks their type and components before scanning. The server exposes paginated findings, individual evidence and inline report export for scans created during that server instance. Inline JSON reports omit the selected project path. The dynamic-analysis request returns instructions for a human. A host that forwards tool results to a model controls the destination of the returned evidence.

## Optional explanations and runtime

The AI module derives one request from one saved observation and the selected provider, endpoint and model. Previewing shows the destination and JSON body before the user approves the request. The send path rebuilds the request and checks the exact preview. The body contains the rule, category, CWE, evidence, explanation and guidance. Ollama connectivity is a separate metadata check restricted to literal loopback addresses. Hosted connections occur on approved explanation requests. Where supported, credentials are keyed by provider and endpoint in the OS credential store. The request client disables redirects, enforces a timeout and limits the response body. Returned text is displayed as an unverified explanation.

The fixed runtime fixture has its own approval and isolation checks. See [Runtime isolation](SECURITY_MODEL_RUNTIME.md). The experimental CodeT5 entry point uses a separate operator-configured local model directory and Python interpreter. Its output stays separate from the static scan history.

## Verification

`cargo test --locked -p security-core --test workflows` checks cancellation, relative paths, multiply linked files, parser coverage reporting, SQLite reopen and duplicate handling, report metadata and coordinates, and the preview and approval flow. The AI test serves Ollama responses from a temporary loopback listener. OpenAI, Anthropic and compatible-provider cases check serialized previews without sending requests.

Whole-scan resource exhaustion returns bounded partial results with a coverage diagnostic. Explicit cancellation returns no Scan. The store accepts schema version 1. The app exposes database initialization failures to its caller.
