# Security model

The normal scan reads source, Cargo.toml and Cargo.lock as local data. It never builds the selected crate, executes build scripts, loads procedural macros or starts a network service. The Rust parser and the advisory dataset are within the trusted application boundary. Parsing bugs, incomplete patterns and preexisting rights to filesystem contents remain relevant.

## Filesystem and persistence

The operator grants one directory capability to each MCP connection. The Rust worker opens it once; paths received later are relative. It rejects parent traversal, absolute paths, links/reparse points and selected files with multiple hard links. The operator controls the root and its parent at startup. The interactive desktop accepts paths through the native project picker or a process startup argument. Source enumeration has file, depth, entry, byte, result and time limits. A single selected project, its files and generated tool output are all untrusted. Source code in evidence can contain misleading instructions or secrets.

Completed scans store local paths, rules, bounded text and observations in SQLite. The database follows the current user's local application data directory; HELINITY_DB selects an alternative. Unix creates private directories and database files. Windows inherits the user's application-directory ACLs. SQLite provides ordinary local storage without built-in encryption. Use a protected account/volume appropriate to the sources. A person or service with access to the account could read its scan history. The app does not store provider credentials there.

## Interfaces and approvals

- MCP exposes ten local tools and session-owned result IDs. Report export returns content to the client. No agent-selected destination, shell command or runtime approval is accepted. Reviewers should treat all extracts as untrusted text.
- Desktop file dialogs, source selection, static scan, history, export and AI requests cross a native IPC boundary. The packaged webview uses local assets, restricted navigation and a restrictive CSP. The application declines existing export filenames. AI transmission requires a native confirmation naming the destination and contents.
- CLI explanations require a terminal and a fresh approval of the exact payload. Secrets live in an OS credential backend where supported. Provider errors do not trigger a fallback. Hosted providers can process the approved evidence under their own terms. AI answers are unverified text.
- Dynamic execution requires human approval and a verified pinned isolation environment. The runtime supports one project-authored arithmetic fixture. It cannot execute an agent-selected target, arbitrary Cargo arguments, downloaded code or payloads. Isolation shares the container engine kernel. [Runtime security model](SECURITY_MODEL_RUNTIME.md)
- Experimental CodeT5 accepts two specific exports by SHA-256, loads safetensors offline and emits a separate experimental result. The V3 operational policy raised no alerts on the three positive cases in the paired evaluation. Forced decisions detected one of the three.

## Residual limitations

The static engine examines a narrow subset of syntax. It has no type resolution, interprocedural flow analysis or proof of exploitability. Concurrent worktree changes may produce an inconsistent snapshot across files. A bounded parser operation finishes before cancellation is observed. An observed dependency version match can still depend on platform, features or runtime reachability. Credential storage, filesystem permissions, external providers and the operating system remain outside the application’s absolute control.
