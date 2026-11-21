# CLI guide

The native executable is `helinity`. The commands below assume it is on PATH. The installer also places it under `.rust-security/` in the scanner checkout.

~~~console
helinity scan fixtures/static
helinity scan fixtures/static/controls.rs --json
helinity history
helinity findings --scan SCAN_ID
helinity report --format json --scan SCAN_ID
helinity report --format sarif --scan SCAN_ID
helinity doctor
helinity runtime status
helinity runtime request
helinity mcp --root /absolute/path/to/a/project
~~~

A completed scan receives an ID. The shell can redirect a report to a file. Without a scan ID the CLI selects the latest saved run. Machine-readable output goes to stdout, while interactive file progress and errors go to stderr. Ctrl+C requests cancellation before committing the scan. History stores project paths, evidence and bounded excerpts locally. Set HELINITY_DB to an absolute database path to isolate a test or use an encrypted volume. Inspect the coverage diagnostics along with findings.

The static fixture directory deliberately contains source-only examples and a small lockfile. It need not build. Never invoke Cargo inside a project received for source review. The scanner reads Cargo.toml as data.

`helinity runtime run-fixture` requires an interactive local terminal, the exact approval phrase, supported local isolation and a trusted pinned image. The request command describes these requirements. [Runtime prerequisites](SECURITY_MODEL_RUNTIME.md)

`helinity ml --model-dir PATH_TO_ORIGINAL_MODEL path/to/file.rs` uses HELINITY_ML_PYTHON, an absolute path to the earlier Helinity inference interpreter. Only the pinned V2 and V3 checkpoints with the original tokenizer, eight matching assets and local safetensors are accepted. Scores never modify a stored static finding. No model downloads occur. Unknown CWE and abstention remain valid outcomes.

[AI preview and interactive key setup](AI_PROVIDER_GUIDE.md) · [Installation and platform validation](INSTALL.md)

Use `helinity review SCAN_ID QUESTION` for a bounded search of saved observations. Use `helinity compare BEFORE AFTER` for per-file, per-rule and per-tool count changes in two scans of the same target. A count decrease does not establish a fix.

