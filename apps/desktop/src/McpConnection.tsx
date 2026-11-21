import { useEffect, useState } from "react";
import { ChevronRight, Copy, FolderOpen } from "lucide-react";
import { call, native } from "./model";
import "./mcp-connection.css";

type Setup = { command: string; python: string | null };
const absolute = (path: string) => /^(?:\/|[A-Za-z]:[\\/]|\\\\)/.test(path) && !/[\x00-\x1f\x7f]/.test(path);

export function McpConnection() {
  const [setup, setSetup] = useState<Setup>();
  const [root, setRoot] = useState("");
  const [python, setPython] = useState("");
  const [format, setFormat] = useState("codex");
  const [advanced, setAdvanced] = useState(false);
  const [choosing, setChoosing] = useState(false);
  const [message, setMessage] = useState("");
  const [setupError, setSetupError] = useState("");
  useEffect(() => {
    let active = true;
    if (native) call<Setup>("mcp_setup").then(value => {
      if (!active) return;
      setSetup(value);
      setPython(value.python ?? "");
      setAdvanced(!value.python);
    }).catch(error => { if (active) setSetupError(String(error)); });
    return () => { active = false; };
  }, []);

  const invalidRoot = root !== "" && !absolute(root);
  const invalidPython = python !== "" && !absolute(python);
  const ready = setup && absolute(root) && absolute(python);
  const env = { HELINITY_MCP_PYTHON: python, HELINITY_MCP_SHARE_SOURCE: "0" };
  const args = ["mcp", "--root", root];
  const spec = ready ? format === "codex"
    ? `[mcp_servers.helinity]\ncommand = ${JSON.stringify(setup.command)}\nargs = ${JSON.stringify(args)}\n\n[mcp_servers.helinity.env]\nHELINITY_MCP_PYTHON = ${JSON.stringify(python)}\nHELINITY_MCP_SHARE_SOURCE = "0"`
    : JSON.stringify({ mcpServers: { helinity: { command: setup.command, args, env } } }, null, 2) : "";

  async function choose() {
    setChoosing(true);
    try {
      const path = await call<string | null>("choose_mcp_root");
      if (path) { setRoot(path); setMessage(""); }
    } catch (error) { setMessage(String(error)); }
    finally { setChoosing(false); }
  }
  async function copyConfig() {
    try { await navigator.clipboard.writeText(spec); setMessage("Configuration copied."); }
    catch { setMessage("Select and copy the configuration below."); }
  }
  return <div className="mcp-connection">
    <p className="mcp-intro">Connect an AI client to Helinity’s scan tools over stdio.</p>
    {setupError && <p className="mcp-error" role="alert">{setupError}</p>}
    <section className="mcp-fields" aria-label="Connection settings">
      <div className="mcp-field">
        <label htmlFor="mcp-client">AI client</label>
        <select id="mcp-client" value={format} onChange={event => { setFormat(event.target.value); setMessage(""); }}>
          <option value="codex">Codex (GPT)</option><option value="json">Other stdio client (JSON)</option>
        </select>
      </div>
      <div className="mcp-field">
        <label htmlFor="mcp-root">Project folder</label>
        <div className="mcp-path">
          <input id="mcp-root" value={root} spellCheck={false} autoComplete="off" placeholder="Absolute project folder"
            aria-invalid={invalidRoot || undefined} aria-describedby="mcp-root-help"
            onChange={event => { setRoot(event.target.value); setMessage(""); }}/>
          <button className="button" disabled={!native || choosing} onClick={() => void choose()}><FolderOpen size={15}/> Browse</button>
        </div>
        <p id="mcp-root-help" className="mcp-hint">{invalidRoot ? "Enter an absolute path or browse for a folder." : "The client can inspect findings in this folder. Raw source excerpts are off by default."}</p>
      </div>
      <div className="mcp-advanced">
        <button className="mcp-disclosure" aria-expanded={advanced} aria-controls="mcp-interpreter" onClick={() => setAdvanced(!advanced)}>
          <ChevronRight aria-hidden="true" size={15}/> Advanced settings
        </button>
        <div className="mcp-field" id="mcp-interpreter" hidden={!advanced}>
          <label htmlFor="mcp-python">Python interpreter</label>
          <input id="mcp-python" value={python} spellCheck={false} autoComplete="off" placeholder="Absolute path to Python"
            aria-invalid={invalidPython || undefined} aria-describedby="mcp-python-help"
            onChange={event => { setPython(event.target.value); setMessage(""); }}/>
          <p className="mcp-hint" id="mcp-python-help">{invalidPython ? "Enter the full path to the Python executable." :
            "Use a Python environment with the MCP SDK installed."}</p>
        </div>
      </div>
    </section>
    {spec && <section className="mcp-output" aria-labelledby="mcp-output-title">
      <div className="mcp-output-head"><h2 id="mcp-output-title">Client configuration</h2><button className="button" onClick={() => void copyConfig()}><Copy size={15}/> Copy</button></div>
      <p className="mcp-hint">{format === "codex" ? "Add this entry to your Codex config.toml, then reopen Codex." : "Add this entry to your client’s MCP configuration, then reconnect."}</p>
      <pre id="mcp-config" tabIndex={0} aria-label="Generated client configuration">{spec}</pre>
    </section>}
    {message && <p role="status" className="mcp-feedback">{message}</p>}
  </div>;
}
