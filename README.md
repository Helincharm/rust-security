# Rust Security

**Copy this prompt into your coding assistant**

> Install Rust Security from https://github.com/Helincharm/rust-security. Follow INSTALL.md, connect it to my MCP client for the Rust project I choose, and verify the connection by scanning the included fixture and opening one finding at its source line. Tell me which client and project folder you configured.

Rust Security reviews Rust source and Cargo dependencies locally. Use the CLI for a single scan, the desktop app to inspect a finding alongside its source, or an MCP client such as Codex or Claude Code to request a scan and retrieve evidence. The scanner works without a model or an API key.

## Installation

Use a coding assistant with terminal access on the machine where your MCP client runs. It needs access to this repository and to the project you select. For manual installation, follow the [setup and connection guide](INSTALL.md).

## What a scan returns

- **Source findings** identify a pattern recognized by the Rust analyzer and give its file, line, column and review guidance.
- **Dependency findings** identify a version in a crates.io lockfile that matches an entry in the bundled RustSec snapshot.
- **Analysis warnings** describe files the analyzer could not fully inspect. These are counted separately from security findings.

A clean scan means the enabled checks produced no findings in the analyzed code. Static review does not establish runtime exploitability. The desktop keeps the source evidence locally. Source sharing with an MCP client is opt-in.

[Detection rules](TOOL_ADAPTERS.md) · [Architecture](ARCHITECTURE.md) · [Security model](SECURITY_MODEL.md)
