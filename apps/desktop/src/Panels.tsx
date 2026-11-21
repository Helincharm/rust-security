import { findingTitle } from "./model";

import { useEffect, useRef, useState } from "react";

import { Activity, ArrowRight, Bot, CircleHelp, FileCode2, LockKeyhole, RefreshCw, Terminal, X } from "lucide-react";

import { call, native, providers, severityOf, type AiConfig, type Finding, type RuntimeInfo, type Scan } from "./model";



export function AiSettings({ config, onSave }: { config: AiConfig; onSave: (config: AiConfig) => void }) {

  const [draft, setDraft] = useState(config);

  const [status, setStatus] = useState("");

  const [busy, setBusy] = useState(false);



  async function check() {

    setBusy(true);

    setStatus("Checking the local endpoint…");

    try {

      setStatus(await call<string>("ai_connectivity", { config: draft }));

    } catch (reason) {

      setStatus(String(reason));

    } finally {

      setBusy(false);

    }

  }



  return <section className="panel"><div className="panel-head"><h2>Review provider</h2><Bot size={18} /></div>

    <form className="panel-body" onSubmit={event => {

      event.preventDefault();

      const endpoint = new URL(draft.endpoint);

      if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {

        setStatus("Remove embedded credentials, query parameters and fragments from the endpoint.");

        return;

      }

      onSave({ ...draft, model: draft.model.trim() });

      setStatus("");

    }}>

      <p>Request an explanation from a finding after reviewing the exact text that will be sent.</p>

      <div className="form-grid">

        <label>Provider<select value={draft.provider} onChange={event => {

          const next = providers.find(entry => entry.id === event.target.value)!;

          setDraft({ provider: next.id, model: next.model, endpoint: next.endpoint });

          setStatus("");

        }}>{providers.map(entry => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label>

        <label>Model<input required value={draft.model} placeholder="Enter a model ID" onChange={event => setDraft({ ...draft, model: event.target.value })} /></label>

        <label className="wide">Endpoint<input required type="url" value={draft.endpoint} placeholder="https://…" onChange={event => setDraft({ ...draft, endpoint: event.target.value })} /></label>

      </div>

      <div className="inline-info"><LockKeyhole size={17} /><p>Helinity stores the endpoint and model on this device. External providers use credentials configured through the CLI and Windows Credential Manager.</p></div>

      <div className="actions">

        {<button className="button" type="button" disabled={!native || busy || !draft.endpoint || !draft.model.trim()} onClick={() => void check()}><Activity size={16} /> Check connection</button>}

        <button className="button primary" disabled={!native || !draft.model.trim()}>Save settings</button>

      </div>

      {status && <p className="status-message" role="status">{status}</p>}

    </form></section>;

}



export function FindingDetail({ scan, finding, config, close, selectFinding }: { scan: Scan; finding: Finding; config: AiConfig; selectFinding: (f: Finding) => void; close: () => void }) {

  const dialog = useRef<HTMLDialogElement>(null);

  const [preview, setPreview] = useState("");

  const [consent, setConsent] = useState(false);

  const [review, setReview] = useState("");

  const [busy, setBusy] = useState(false);

  const [error, setError] = useState("");

  const provider = providers.find(entry => entry.id === config.provider);

  const findingIndex = scan.findings.indexOf(finding);

  const args = { config, scanId: scan.id, findingIndex };

  const location = finding.line > 0

    ? `${finding.path}:${finding.line}${finding.column > 0 ? `:${finding.column}` : ""}`

    : finding.path;

  const snapshotLocation = finding.end_line > finding.line

    ? `${location}–${finding.end_line}${finding.end_column > 0 ? `:${finding.end_column}` : ""}`

    : location;

  const sourceLines = finding.source_context ? finding.source_context.split("\n") : [];
  if (finding.source_line !== undefined && finding.source_line !== null) sourceLines[0] = finding.source_line;
  const highlightStart = finding.column - 1;
  const highlightEnd = finding.end_line === finding.line ? finding.end_column - 1 : undefined;


  useEffect(() => {

    const element = dialog.current;

    element?.showModal();

    return () => element?.close();

  }, []);



  async function prepare() {

    setBusy(true);

    setError("");

    setConsent(false);

    try {

      setPreview(await call<string>("ai_preview", args));

    } catch (reason) {

      setError(String(reason));

    } finally {

      setBusy(false);

    }

  }



  async function send() {

    setBusy(true);

    setError("");

    setConsent(false);

    try {

      setReview(await call<string>("ai_review", { ...args, approvedPreview: preview }));

    } catch (reason) {

      setError(String(reason));

    } finally {

      setBusy(false);

    }

  }



  return <dialog className="detail" aria-labelledby="finding-title" ref={dialog} onCancel={event => { event.preventDefault(); close(); }}>

    <header className="detail-top"><FileCode2 size={17} /><span>Helinity</span><span>/</span><strong>Code review</strong><button autoFocus className="icon-button" aria-label="Close finding" onClick={close}><X size={20} /></button></header>

    <div className="code-layout"><aside className="code-files"><h3>Sources with evidence</h3>

      {[...new Set(scan.findings.map(f => f.path))].map(path => <button key={path} aria-pressed={finding.path === path} onClick={() => { if (path !== finding.path) selectFinding(scan.findings.find(f => f.path === path)!); }}><FileCode2 size={14}/>{path}</button>)}

      </aside><section className="code-pane"><div className="code-toolbar"><code>{finding.path}</code><span>Saved excerpt</span></div>

      <h2>Source snapshot</h2><code className="snapshot-location">{snapshotLocation}</code>

      {!!sourceLines.length ? <div className="source-lines">{sourceLines.map((line, i) => <div key={i}>
        <span>{finding.line ? finding.line + i : "·"}</span>
        <code>{i === 0 && finding.source_line != null && highlightStart >= 0 ? <>
          {line.slice(0, highlightStart)}<mark>{line.slice(highlightStart, highlightEnd)}</mark>
          {highlightEnd !== undefined && line.slice(highlightEnd)}
        </> : line}</code>
      </div>)}</div>

       : <p>No source excerpt was saved for this finding.</p>}

      {scan.findings.filter(f => f.path === finding.path).length > 1 && <label className="code-picker">Finding in this file<select value={findingIndex} onChange={e => { const item = scan.findings[Number(e.target.value)]; if (item) selectFinding(item); }}>{scan.findings.map((f,i) => f.path === finding.path && <option key={i} value={i}>{f.id} · line {f.line}</option>)}</select></label>}</section>

      <div className="detail-body">

      <span className={`severity ${severityOf(finding)}`}>{finding.severity}</span>

      <h2 id="finding-title">{findingTitle(finding)}</h2>

      <code className="detail-path">{location}</code>

      <dl className="fact-grid">

        <div><dt>Rule</dt><dd>{finding.id}</dd></div>

        <div><dt>Tool</dt><dd>{finding.tool}</dd></div>

        <div><dt>CWE</dt><dd>{finding.cwe || "—"}</dd></div>

        <div><dt>Confidence</dt><dd>{finding.confidence}</dd></div>

      </dl>

      <section><h3>Explanation</h3><p>{finding.explanation}</p></section>

      <section><h3>Remediation</h3><p>{finding.remediation}</p></section>

      <section><h3>Evidence</h3><pre>{finding.evidence || "Evidence was omitted by the analyzer."}</pre></section>



      <section className="ai-review">

        <h3><Bot size={17} /> AI review</h3>

        <p>{config.model ? `${provider?.name || config.provider} · ${config.model}` : "Choose a provider and model in AI settings."}</p>

        {!preview && <button className="button" disabled={!native || !config.model || busy} onClick={() => void prepare()}>{busy ? "Preparing…" : "Preview request"} <ArrowRight size={15} /></button>}

        {preview && <>

          <p className="mono detail-path">Destination · {config.endpoint}</p>

          <pre aria-label="Exact request preview">{preview}</pre>

          <div className="inline-info"><CircleHelp size={17} /><p>This sends the text above to an external provider. Provider terms and billing may apply.</p></div>

          <label className="consent"><input type="checkbox" checked={consent} disabled={busy} onChange={event => setConsent(event.target.checked)} />

            <span>I approve sending this exact text to the selected provider.</span></label>

          <button className="button primary" disabled={busy || !consent} onClick={() => void send()}>{busy ? "Confirm in the native dialog…" : "Send approved request"} <ArrowRight size={15} /></button>

        </>}

        {error && <p className="status-message error-text" role="alert">{error}</p>}

        {review && <section><h3>Provider response</h3><pre className="response">{review}</pre></section>}

      </section>

    </div>

    </div>

  </dialog>;

}



function runtimeValue(value: unknown) {

  if (value === null) return "—";

  if (typeof value === "boolean") return value ? "Yes" : "No";

  if (typeof value === "string" || typeof value === "number") return String(value);

  return JSON.stringify(value);

}



export function RuntimePanel({ info, busy, refresh }: { info: RuntimeInfo | null; busy: boolean; refresh: (request: boolean) => Promise<void> }) {

  useEffect(() => {

    if (native && !info && !busy) void refresh(false);

    // Load backend status on entry. Explicit actions handle subsequent refreshes.

  }, []);



  return <section className="panel">

    <div className="panel-head"><h2>Isolated runtime</h2><Terminal size={18} /></div>

    <div className="panel-body">

      <p>Check sandbox availability or review the request requirements for the bundled harmless fixture.</p>

      <div className="actions">

        <button className="button" disabled={!native || busy} onClick={() => void refresh(false)}><RefreshCw size={15} /> Refresh status</button>

        <button className="button primary" disabled={!native || busy} onClick={() => void refresh(true)}>Review fixture request <ArrowRight size={16} /></button>

      </div>

      {busy && <p role="status">Checking runtime…</p>}

      {info && <dl className="runtime-details">{Object.entries(info).map(([key, value]) => <div key={key}>

        <dt>{key.replaceAll("_", " ")}</dt><dd>{runtimeValue(value)}</dd>

      </div>)}</dl>}

    </div>

  </section>;

}

