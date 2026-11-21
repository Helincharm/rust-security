# Tool adapters

## Rust AST

The built-in `static-ast` adapter parses developer-selected Rust text with `syn`. It recognizes the following local expression shapes and reports a review finding with a source range. It never compiles or executes the input, resolves imports, expands macros or reads files named in it.

| Rule | CWE | Evidence |
| --- | --- | --- |
| HEL-RUST-001 | CWE-89 | A recognized `sqlx` query call accepts a direct format expression with nonliteral data. |
| HEL-RUST-002 | CWE-78 | `std::process::Command::new` directly takes a program name returned by `std::env::var`. |
| HEL-RUST-003 | CWE-22 | A standard filesystem read directly takes the result of joining a path with a value returned by `std::env::var`. |
| HEL-RUST-004 | CWE-20 | Direct numeric byte indexing uses an environment-derived string without a length check on the expression. |
| HEL-RUST-005 | CWE-88 | A shell-style quoting branch returns its input unchanged when a literal byte predicate omits an argument-sensitive character. |
| HEL-RUST-006 | CWE-22 | A filesystem path builder appends externally supplied components without a recognized Windows prefix check. |
| HEL-RUST-007 | CWE-20 | A constructor discards a decoded tag before storing the bytes; an accessor assumes conversion of that tag succeeds. |
| HEL-RUST-008 | CWE-400 | A recursive compiler dispatches repeated work while its empty-expression case consumes no measured compilation budget. |
| HEL-RUST-009 | CWE-770 | A stream-error handler forwards a reset reason and initiator to its reset sender and returns success without a local budget check. |
| HEL-RUST-010 | CWE-367 | Recursive deletion reopens the pathname of an enumerated child after checking its directory-entry type. |

These syntactic rules recognize selected local bindings, branches and same-implementation call relationships. Coverage depends on the expression shape. The scanner does not establish whole-program reachability, resolve types or evaluate build configuration. For HEL-RUST-009, a compatible sender defined in the same file suppresses the finding because it may enforce its own budget. Review external senders and connection-level controls manually. A finding gives the reviewer a location to check in context. The reported evidence names the matched shape and omits literal values from the selected source. Source ranges use one-based UTF-16 columns and exclusive ends. The fixtures under `fixtures/static` are source text for the parser tests.

## Offline Cargo.lock

The built-in `cargo-lock` adapter reads package entries as TOML and compares crates.io versions against the bundled advisory set using SemVer precedence. It skips git, local and alternate-registry sources. High confidence on a dependency finding describes the version match. The upstream advisory establishes platform, feature and API-use conditions relevant to the application.

The snapshot selects 18 CC0-1.0 records from RustSec revision `3cc7c27472f3f2c301ae58783d729278950db6e7`. The bundled file carries each record’s upstream link, digest, attribution and terms. It excludes advisory prose. Scan-time matching is offline and the snapshot has limited historical coverage. [Metadata provenance and license](THIRD_PARTY_NOTICES.md)

## Limits and diagnostics

The framework reads at most 256 KiB per file. The standalone static-analysis crate also enforces its own 2 MiB ceiling and returns at most 512 findings for each file. The AST adapter also caps tokens, nesting and expression complexity. Malformed input, limit hits and parser failures appear as analysis warnings in a separate collection. A coverage diagnostic may have no source range.

## Execution and optional adapters

Cargo manifests are parsed as TOML. Cargo metadata, check, Clippy, audit and deny are not launched against a selected workspace. Cargo configuration, proc macros and build scripts can cross execution boundaries. The integrated dependency analyzer instead checks lockfile registry identity, package and affected ranges against its pinned local snapshot. The built-in rules and dependency scanner need no Cargo installation.

The runtime adapter supports requests, preflight, refusal and an opt-in embedded arithmetic fixture under verified isolation. Successful execution requires the isolation controls in the runtime design. Miri, fuzzing, ASan and TSan report unavailable. The project provides no harness for executing an arbitrary target. [Runtime design](SECURITY_MODEL_RUNTIME.md)

The optional CodeT5 adapter verifies eight pinned export assets, reads real Rust function spans with Tree-sitter and emits separate binary scores or abstentions. It accepts the original V2/V3 checkpoints. Hosted inference does not participate in static analysis. [CLI](CLI_GUIDE.md) · [AI providers](AI_PROVIDER_GUIDE.md)
