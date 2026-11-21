# Optional AI provider setup

The local scanner needs no AI. The desktop can save provider, model and endpoint preferences. Windows stores an optional secret through the OS credential manager. Linux builds use the user's kernel keyring when available. A missing backend fails explicitly. The framework stores no provider keys in SQLite, report files or application logs.

| Provider | Base URL | Behavior |
|---|---|---|
| openai | https://api.openai.com/v1 | Explicit model, constrained origin, bearer credential and chat/completions. |
| anthropic | https://api.anthropic.com/v1 | Explicit model and constrained origin. Adapter uses Messages with the provider's version header. |
| compatible | An explicitly chosen HTTPS API base, or HTTP on literal loopback | OpenAI-compatible chat/completions schema. A credential is associated with the selected base URL. |

~~~console
helinity ai-key --provider openai --model YOUR_MODEL --endpoint https://api.openai.com/v1
helinity explain --scan SCAN_ID --index 0 --provider openai --model MODEL_ID --endpoint https://api.openai.com/v1
~~~

The first command reads a secret with terminal echo disabled. The second only previews. Passing --send requires a human terminal confirmation after the exact provider, destination, model and serialized payload are visible. The desktop requires native confirmation for an outbound request. A changed payload invalidates the preview. The prompt can include the analyzer evidence description and remediation, with the source excerpt omitted. It excludes database history and full files. Provider output is unverified advice. It cannot run commands or upgrade an observation to a confirmed finding.

A Windows desktop connectivity check for a hosted endpoint requires native approval of a credentialed GET to its model-list route. This request sends no project evidence. A hosted service may paginate its model list. On platforms lacking the native consent mechanism, external desktop actions fail closed.

Only loopback test doubles and request previews were used to validate the adapters here. No live paid model call was made. Network redirects and provider substitution are disabled. [Core tests](crates/security-core/tests/workflows.rs)


## Use an existing GPT client

Open MCP connection in Helinity Desktop, choose the folder to share and copy its config into your Codex client. Select the model in the client. Helinity exposes stdio tools and does not require model weights or an inference service. [Installation and MCP setup](INSTALL.md)
