const logo = new URL("./helinity-h.png", import.meta.url).href;
import { CoverageWarnings } from "./CoverageWarnings";
import "./nav-shell.css";
import { findingTitle } from "./model";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import {

  Activity, ArrowDownToLine, ArrowRight, ChevronRight, CircleHelp, FileCode2,

  FileText, FolderOpen, ListFilter, ScanLine, ScanSearch, Search, Settings2,

  ShieldCheck, ShieldAlert, Square, X,

} from "lucide-react";

import {

  call, dateLabel, firstConfig, leaf, native, priority, runScan, severities, severityOf,

  type AiConfig, type Finding, type Progress, type RuntimeInfo, type Scan, type Summary,

} from "./model";

import { AiSettings, FindingDetail, RuntimePanel } from "./Panels";

import { EvidenceReview } from "./EvidenceReview";



import { McpConnection } from "./McpConnection";
import { ActivityLog, useActivityLog } from "./ActivityLog";



const workspaceViews = [
  { id: "evidence", label: "Review" },
  { id: "overview", label: "Scans" },
  { id: "explorer", label: "Files" },
  { id: "reports", label: "Reports" },
] as const;

const settingsViews = [
  { id: "mcp", label: "MCP connection" },
  { id: "ai", label: "AI provider" },
  { id: "runtime", label: "Runtime" },
] as const;

const primaryNavigation = [
  { id: "evidence", label: "Workspace", icon: ScanSearch },
  { id: "findings", label: "Findings", icon: ShieldAlert },
  { id: "activity", label: "Activity", icon: Activity },
] as const;

type Page = (typeof workspaceViews)[number]["id"] | (typeof settingsViews)[number]["id"] | "findings" | "activity";

function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {

  return <div className="empty"><span className="empty-icon">{icon}</span><h3>{title}</h3>{children}</div>;

}



function Severity({ finding }: { finding: Finding }) {

  const severity = severityOf(finding);

  return <span className={`severity ${severities.includes(severity) ? severity : "info"}`}>{severity}</span>;

}



function FindingRows({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {

  return <div className="list" aria-label="Findings">

    {findings.map(finding => <button className="row finding-row" key={`${finding.id}-${finding.tool}-${finding.path}-${finding.line}-${finding.column}`} onClick={() => onSelect(finding)}>

      <Severity finding={finding} />

      <span className="row-content"><strong>{findingTitle(finding)}</strong><code title={finding.path}>{finding.path}:{finding.line}</code></span>

      <span className="row-extra mono">{finding.cwe || finding.tool}</span>

      <ChevronRight size={15} />

    </button>)}

  </div>;

}



export default function App() {

  const [page, setPage] = useState<Page>("evidence");

  const [history, setHistory] = useState<Summary[]>([]);

  const [scan, setScan] = useState<Scan | null>(null);

  const [target, setTarget] = useState("");

  const [picking, setPicking] = useState(false);

  const [running, setRunning] = useState(false);

  const [cancelling, setCancelling] = useState(false);

  const [progress, setProgress] = useState<Progress | null>(null);

  const [finding, setFinding] = useState<Finding | null>(null);

  const [filter, setFilter] = useState("");

  const [facets, setFacets] = useState({ cwe: "", tool: "", verification_status: "" });

  const resetFacets = () => setFacets({ cwe: "", tool: "", verification_status: "" });

  const [search, setSearch] = useState("");

  const [fileFilter, setFileFilter] = useState("");

  const [ai, setAi] = useState(firstConfig);

  const [error, setError] = useState("");

  const [notice, setNotice] = useState("");

  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);

  const [runtimeBusy, setRuntimeBusy] = useState(false);

  const [baseBusy, setBaseBusy] = useState(false);

  const [exporting, setExporting] = useState(false);

  const { entries, record } = useActivityLog();

  function showEvidence(item: Finding) {

    setFinding(item);

    if (scan) record(scan.id, {title: "Evidence opened", detail: item.path, finding: scan.findings.indexOf(item)});

  }

  const heading = useRef<HTMLHeadingElement>(null);
  const historyRequest = useRef(0);
  const hasScan = useRef(false);

  useEffect(() => { hasScan.current = scan !== null; }, [scan]);

  const refreshHistory = useCallback(async () => {
    const request = ++historyRequest.current;
    try {
      const entries = await call<Summary[]>("history");
      if (request !== historyRequest.current) return;
      setHistory(entries);
      if (!hasScan.current && entries[0]) {
        const latest = await call<Scan>("get_scan", { id: entries[0].id });
        if (request === historyRequest.current) setScan(current => current ?? latest);
      }
    } catch (reason) {
      if (request === historyRequest.current) setError(String(reason));
    }
  }, []);

  useEffect(() => {
    if (!native) return;

    let active = true;
    setBaseBusy(true);

    call<string | null>("current_target").then(path => {

      if (active && path) setTarget(path);

    }).catch(reason => { if (active) setError(String(reason)); });

    void refreshHistory().finally(() => { if (active) setBaseBusy(false); });
    const onFocus = () => { void refreshHistory(); };
    window.addEventListener("focus", onFocus);
    return () => {
      active = false;
      window.removeEventListener("focus", onFocus);
      historyRequest.current++;
    };
  }, [refreshHistory]);



  function go(next: Page) {

    if (next !== page) setNotice("");
    setPage(next);

    setFinding(null);

    if (native && (next === "evidence" || next === "reports")) void refreshHistory();

    requestAnimationFrame(() => heading.current?.focus());

  }



  async function choose(folder: boolean) {

    setError("");

    setPicking(true);

    try {

      const path = await call<string | null>("choose_target", { folder });

      if (path) setTarget(path);

    } catch (reason) {

      setError(String(reason));

    } finally {

      setPicking(false);

    }

  }



  async function start() {

    setError("");

    setNotice("");

    setProgress(null);

    setRunning(true);

    try {

      const result = await runScan(setProgress);

      if (result) {

        setScan(result);

        record(result.id, {title: "Scan completed", detail: `${result.files.length} files · ${result.findings.length} findings · ${result.warnings.length} analysis warnings`, tool: "scan_target"});

        setFinding(null);

        setFilter("");

        setSearch("");

        setFileFilter("");

        setNotice(`Scan complete. ${result.files.length} files · ${result.findings.length} findings · ${result.warnings.length} analysis warnings.`);

        await refreshHistory();

      } else {

        setNotice("Scan cancelled.");

      }

    } catch (reason) {

      setError(String(reason));

    } finally {

      setRunning(false);

      setCancelling(false);

    }

  }



  async function cancel() {

    setCancelling(true);

    try {

      if (!await call<boolean>("cancel_scan")) setCancelling(false);

    } catch (reason) {

      setError(String(reason));

      setCancelling(false);

    }

  }



  async function loadScan(id: string) {

    setBaseBusy(true);

    setError("");

    try {

      setScan(await call<Scan>("get_scan", { id }));

      setFinding(null);

      setFileFilter("");

      setFilter("");

      setSearch("");

    } catch (reason) {

      setError(String(reason));

    } finally {

      setBaseBusy(false);

    }

  }



  async function exportReport(format: "json" | "sarif") {

    if (!scan) return;

    setError("");

    setNotice("");

    setExporting(true);

    try {

      const path = await call<string | null>("export_report", { id: scan.id, format });

      if (path) setNotice(`Exported ${format.toUpperCase()} to ${path}`);

    } catch (reason) {

      setError(String(reason));

    } finally {

      setExporting(false);

    }

  }



  async function getRuntime(request: boolean) {

    setRuntimeBusy(true);

    setError("");

    try {

      setRuntime(await call<RuntimeInfo>("runtime_info", { request }));

    } catch (reason) {

      setError(String(reason));

    } finally {

      setRuntimeBusy(false);

    }

  }



  function saveAi(config: AiConfig) {

    setAi(config);

    try {

      localStorage.setItem("helinity.ai", JSON.stringify(config));

      setNotice("Provider settings saved.");

    } catch {

      setNotice("Provider settings are active for this session.");

    }

  }



  const findings = [...(scan?.findings || [])].sort(priority);

  const query = search.trim().toLowerCase();

  const visible = findings.filter(item =>

    (!facets.cwe || String(item.cwe ?? "Unknown") === facets.cwe) &&

    (!facets.tool || item.tool === facets.tool) &&

    (!facets.verification_status || item.verification_status === facets.verification_status) &&

    (!filter || severityOf(item) === filter) && (!fileFilter || item.path === fileFilter) &&

    (!query || [item.path, findingTitle(item), item.category, item.tool, item.cwe, item.explanation]

      .some(value => String(value || "").toLowerCase().includes(query))));

  const countByPath = new Map<string, number>();

  for (const item of findings) countByPath.set(item.path, (countByPath.get(item.path) || 0) + 1);

  const inWorkspace = workspaceViews.some(view => view.id === page);
  const inSettings = settingsViews.some(view => view.id === page);
  const subpages = inWorkspace ? workspaceViews : inSettings ? settingsViews : [];
  const title = inSettings ? "Settings" : inWorkspace ? "Agent workspace" : page === "findings" ? "Findings" : "Activity log";

  const selection = <div className="target panel">

    <div className="target-main">

      <span className="target-icon"><ScanLine size={25} /></span>

      <div><h2>{target ? leaf(target) : "Select a scan target"}</h2>

        {target ? <code className="target-path" title={target}>{target}</code> :

          <p>Choose a Rust project folder, source file, or Cargo file.</p>}</div>

    </div>

    <div className="actions">

      <button className="button" disabled={!native || picking || running || baseBusy} onClick={() => void choose(true)}><FolderOpen size={16} /> Folder</button>

      <button className="button" disabled={!native || picking || running || baseBusy} onClick={() => void choose(false)}><FileCode2 size={16} /> File</button>

      {running ?

        <button className="button danger" disabled={cancelling} onClick={() => void cancel()}><Square size={14} /> {cancelling ? "Cancelling…" : "Cancel scan"}</button> :

        <button className="button primary" disabled={!target || baseBusy || picking} onClick={() => void start()}>Run scan <ArrowRight size={16} /></button>}

    </div>

    {running && <div className="progress" role="status"><span className="pulse" />

      {progress ? <><span>{progress.files} {progress.files === 1 ? "file" : "files"} checked</span><code title={progress.path}>{progress.path}</code></> : "Starting local analysis…"}

    </div>}

  </div>;



  return <div className="workspace app-shell">
    <aside className="sidebar">
      <div className="brand"><img className="brand-mark" src={logo} alt="" /><div><strong>Helinity</strong></div></div>
      <nav aria-label="Main navigation">
        {primaryNavigation.map(({ id, label, icon: Icon }) => {
          const active = id === "evidence" ? inWorkspace : page === id;
          return <button className={`nav-item ${active ? "active" : ""}`} key={id} aria-label={label} title={label}
            aria-current={active ? "page" : undefined} onClick={() => go(id)}>
            <Icon size={17}/><span>{label}</span>{id === "findings" && !!scan?.findings.length && <span className="nav-count">{scan.findings.length}</span>}
          </button>;
        })}
      </nav>
      <div className="shell-settings"><button className={`nav-item ${inSettings ? "active" : ""}`} aria-label="Settings" title="Settings"
        aria-current={inSettings ? "page" : undefined} onClick={() => go("mcp")}><Settings2 size={17}/><span>Settings</span></button></div>
    </aside>
    <main className="main">
      <div className="content">
        <header className="page-title">
          <h1 ref={heading} tabIndex={-1}>{title}</h1>
          {running ? <span className="scope mono" role="status"><span className="pulse"/>Scanning</span> :
            !inSettings && scan && <span className="scope mono" title={scan.project}><FolderOpen size={15}/>{leaf(scan.project)}</span>}
        </header>
        {subpages.length > 0 && <nav className="section-navigation" aria-label={inSettings ? "Settings sections" : "Workspace sections"}>
          {subpages.map(view => <button key={view.id} aria-current={view.id === page ? "page" : undefined}
            onClick={() => go(view.id)}>{view.label}</button>)}
        </nav>}
        {!native && <div className="notice"><CircleHelp size={16} /> Open Helinity Desktop to use the native scan and report controls.</div>}

        {error && <div className="notice error" role="alert"><ShieldAlert size={17} /><span>{error}</span><button className="icon-button" aria-label="Dismiss error" onClick={() => setError("")}><X size={16} /></button></div>}

        {notice && <div className="notice" role="status"><Activity size={17} /><span>{notice}</span><button className="icon-button" aria-label="Dismiss notice" onClick={() => setNotice("")}><X size={16} /></button></div>}

        {scan && ["overview","reports","findings","evidence","explorer"].includes(page) && <CoverageWarnings warnings={scan.warnings} />}
        {page === "overview" && <>

          {selection}

          <div className="metrics">

            {[["Files scanned", scan?.files.length], ["Findings", scan?.findings.length], ["High priority", scan && findings.filter(f => ["critical", "high"].includes(severityOf(f))).length], ["Saved scans", history.length]].map(([label, value]) =>

              <div className="metric" key={label}><span>{label}</span><strong>{value ?? "—"}</strong></div>)}

          </div>

          <section className="panel"><div className="panel-head"><h2>Priority findings</h2>{scan && <button className="text-button" onClick={() => { setFilter(""); resetFacets(); setSearch(""); setFileFilter(""); go("findings"); }}>View all <ArrowRight size={14} /></button>}</div>

            {findings.length ? <FindingRows findings={findings.slice(0, 5)} onSelect={showEvidence} /> :

              <Empty icon={<ShieldCheck size={22} />} title={scan ? "No findings reported" : "No scan results yet"}>

                <p>{scan ? "Review scan diagnostics in Reports." : "Run a scan to review security findings and their source evidence."}</p></Empty>}</section>

        </>}

        {page === "explorer" && <>

          {selection}

          <section className="panel"><div className="panel-head"><h2>Scanned files</h2>{scan && <span className="mono muted">{scan.files.length} files</span>}</div>

            {scan?.files.length ? <div className="list">{scan.files.map(path => {

              const count = countByPath.get(path) || 0;

              return <button className="row file-row" key={path} onClick={() => { setFilter(""); resetFacets(); setSearch(""); setFileFilter(path); go("findings"); }}>

                <FileCode2 size={16} /><code title={path}>{path}</code><span className="row-extra">{count} findings</span><ChevronRight size={15} /></button>;

            })}</div> : <Empty icon={<FolderOpen size={22} />} title="No scanned files"><p>Files appear here after a completed scan.</p></Empty>}</section>

        </>}

        {page === "explorer" && !!scan?.manifests?.length && <section className="panel">

          <div className="panel-head"><h2>Cargo manifests</h2></div>

          <dl className="panel-body runtime-details">{scan.manifests.map(manifest => <div key={manifest.path}>

            <dt>{manifest.name || "Workspace manifest"}{manifest.version && ` · ${manifest.version}`}</dt><dd>{manifest.path}</dd>

          </div>)}</dl>

        </section>}

        {page === "findings" && <section className="panel">

          <div className="panel-head filters"><label className="input-icon"><Search size={16} /><input placeholder="Search findings" aria-label="Search findings" value={search} onChange={event => setSearch(event.target.value)} /></label>

            <label className="input-icon"><ListFilter size={16} /><select aria-label="Filter severity" value={filter} onChange={event => setFilter(event.target.value)}>

              <option value="">All severities</option>{severities.map(value => <option key={value} value={value}>{value}</option>)}</select></label>

            {(["cwe","tool","verification_status"] as const).map(key => {

              const label = {cwe:"CWE",tool:"analyzer",verification_status:"verification status"}[key];

              const options = [...new Set(findings.map(f => String(f[key] ?? "Unknown")))].sort();

              return <label className="input-icon" key={key}><select aria-label={`Filter ${label}`} value={facets[key]}

                onChange={e => setFacets({...facets,[key]: e.target.value})}>

                <option value="">{`Any ${label}`}</option>{options.map(v=><option key={v} value={v}>{v.replaceAll("_"," ")}</option>)}

              </select></label>;

            })}

            <span className="mono muted">{visible.length} / {findings.length}</span></div>

          {fileFilter && <div className="file-filter"><code>{fileFilter}</code><button className="icon-button" aria-label="Clear file filter" onClick={() => setFileFilter("")}><X size={15} /></button></div>}

          {visible.length ? <FindingRows findings={visible} onSelect={showEvidence} /> :

            <Empty icon={<ShieldCheck size={22} />} title={scan ? "No matching findings" : "No scan results yet"}>{scan && (filter || search || fileFilter || Object.values(facets).some(Boolean)) &&

              <button className="text-button" onClick={() => { setFilter(""); resetFacets(); setSearch(""); setFileFilter(""); }}>Clear filters</button>}</Empty>}

        </section>}

        {page === "reports" && <>

          <section className="panel"><div className="panel-head"><h2>Scan history</h2>{scan && <div className="actions">

            <button className="button" disabled={baseBusy || running} onClick={() => go("evidence")}><ScanSearch size={15} /> Review evidence</button>

            <button className="button" disabled={exporting || baseBusy} onClick={() => void exportReport("json")}><ArrowDownToLine size={15} /> JSON</button>

            <button className="button" disabled={exporting || baseBusy} onClick={() => void exportReport("sarif")}><ArrowDownToLine size={15} /> SARIF</button>

          </div>}</div>

            {history.length ? <div className="list">{history.map(entry => <button className={`row report-row ${scan?.id === entry.id ? "selected" : ""}`} key={entry.id}

              disabled={baseBusy || running || exporting} aria-pressed={scan?.id === entry.id} onClick={() => void loadScan(entry.id)}>

              <FileText size={17} /><span className="row-content"><strong>{leaf(entry.project)}</strong><span>{dateLabel(entry.created_at)}</span></span>

              <span className="row-extra">{entry.files} files · {entry.findings} findings{entry.warning_count > 0 && ` · ${entry.warning_count} analysis warnings`}</span><ChevronRight size={15} /></button>)}</div> :

              <Empty icon={<FileText size={22} />} title={baseBusy ? "Loading history…" : "No saved scans"} />}

          </section>

          {scan && <section className="panel"><div className="panel-head"><h2>Diagnostics</h2></div>

            {scan.diagnostics.length ? <ul className="diagnostics">{scan.diagnostics.map((message, index) => <li key={index}>{message}</li>)}</ul>

              : <p className="panel-copy">This scan produced no diagnostics.</p>}</section>}

        </>}

        {page === "evidence" && !scan && selection}

        {page === "activity" && <ActivityLog scan={scan} entries={entries} open={index => { const item = scan?.findings[index]; if (item) showEvidence(item); }} />}

        <EvidenceReview visible={page === "evidence"} scan={scan} history={history}

          scanBusy={baseBusy || running} openConnection={() => go("mcp")} selectScan={loadScan} openFinding={showEvidence} record={record} openLog={() => go("activity")} />

        {page === "mcp" && <McpConnection />}
        {page === "ai" && <AiSettings config={ai} onSave={saveAi} />}

        {page === "runtime" && <RuntimePanel info={runtime} busy={runtimeBusy} refresh={getRuntime} />}

      </div>


    </main>

    {finding && scan && <FindingDetail key={`${scan.id}-${scan.findings.indexOf(finding)}`} scan={scan} finding={finding} config={ai} selectFinding={showEvidence} close={() => setFinding(null)} />}

  </div>;

}

