import { useRef, useState, type FormEvent } from "react";
import { ArrowRight, ChevronRight, FileCode2, ListChecks, ScanSearch } from "lucide-react";

import { call, dateLabel, leaf, native, type Finding, type Scan, type Summary } from "./model";

import { type RecordEvent } from "./ActivityLog";

type Reference = { index: number; path: string; line: number; rule: string };
function referencedFinding(scan: Scan | null, ref: Reference) {
  const matches = (item?: Finding) => item?.id === ref.rule && item.path === ref.path && item.line === ref.line;
  const indexed = scan?.findings[ref.index];
  return matches(indexed) ? indexed : scan?.findings.find(matches);
}
type LookupEvent = { tool: string; status: string; duration_ms: number; summary: string };
type Result = { answer: string; events: LookupEvent[]; references: Reference[]; provider: string };
type Turn = { question: string; result: Result };
type Sessions = { scanId: string; turns: Turn[] }[];

const storageKey = "helinity.evidence-review.v1";
const retainedScans = 20;
const retainedQuestions = 12;

function readSessions(): Sessions {
  try {
    const data = JSON.parse(localStorage.getItem(storageKey) || "[]");
    if (Array.isArray(data)) {
      return data.filter(entry => typeof entry?.scanId === "string" && Array.isArray(entry.turns))
        .slice(0, retainedScans).map(entry => ({
          scanId: entry.scanId,
          turns: entry.turns.filter((turn: Turn) =>
            typeof turn?.question === "string" && typeof turn.result?.answer === "string" &&
            Array.isArray(turn.result.events) && Array.isArray(turn.result.references),
          ).slice(0, retainedQuestions),
        }));
    }
  } catch {
    // An unavailable or stale session does not prevent an evidence lookup.
  }
  return [];
}

type Props = {
  record: RecordEvent;
  openLog: () => void;
  visible: boolean;
  scan: Scan | null;
  history: Summary[];
  scanBusy: boolean;
  openConnection: () => void;
  selectScan: (id: string) => Promise<void>;
  openFinding: (finding: Finding) => void;
};

export function EvidenceReview({ visible, scan, history, scanBusy, openConnection, selectScan, openFinding, record, openLog }: Props) {

  const [sessions, setSessions] = useState(readSessions);
  const saved = useRef(sessions);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [selectedTurns, setSelectedTurns] = useState<Record<string, number>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [storageError, setStorageError] = useState(false);
  const scanId = scan?.id ?? "";
  const turns = sessions.find(session => session.scanId === scanId)?.turns ?? [];
  const selectedTurn = selectedTurns[scanId] ?? 0;
  const turn = turns[selectedTurn];
  const draft = drafts[scanId] ?? "";
  const busy = pending[scanId];

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const question = draft.trim();
    if (!scanId || !question || busy || scanBusy || !native) return;

    setPending(previous => ({ ...previous, [scanId]: true }));
    setErrors(previous => ({ ...previous, [scanId]: "" }));
    try {
      const result = await call<Result>("investigate_scan", { scanId, question });
      for (const event of result.events) record(scanId, {title: "Lookup completed", detail: event.summary, tool: event.tool, duration: event.duration_ms, finding: result.references[0]?.index});
      const otherSessions = saved.current.filter(session => session.scanId !== scanId);
      saved.current = [
        { scanId, turns: [{ question, result }, ...turns].slice(0, retainedQuestions) },
        ...otherSessions,
      ].slice(0, retainedScans);
      setSessions(saved.current);
      setSelectedTurns(previous => ({ ...previous, [scanId]: 0 }));
      setDrafts(previous => ({ ...previous, [scanId]: "" }));
      try {
        localStorage.setItem(storageKey, JSON.stringify(saved.current));
        setStorageError(false);
      } catch {
        setStorageError(true);
      }
    } catch (reason) {
      setErrors(previous => ({ ...previous, [scanId]: String(reason) }));
    } finally {
      setPending(previous => ({ ...previous, [scanId]: false }));
    }
  }

  const reference = turn?.result.references[0];
  const preview = reference ? referencedFinding(scan, reference) : turn ? undefined : scan?.findings[0];
  return <div className="review-workspace" hidden={!visible}>
    {(scan || history.length > 0) && <section className="panel review-scope" aria-labelledby="review-scan-label">
      <div className="review-scan">
        <label htmlFor="review-scan" id="review-scan-label">Completed scan</label>
        <select id="review-scan" value={scanId} disabled={!history.length || scanBusy}
          onChange={event => void selectScan(event.target.value)}>
          {!scan && <option value="">Select a saved scan</option>}
          {scan && !history.some(entry => entry.id === scan.id) &&
            <option value={scan.id}>{leaf(scan.project)} · {dateLabel(scan.created_at)}</option>}
          {history.map(entry => <option key={entry.id} value={entry.id}>
            {leaf(entry.project)} · {dateLabel(entry.created_at)}
          </option>)}
        </select>

      </div>
      <button className="button" onClick={openConnection}>Connect via MCP <ArrowRight size={15}/></button>
    </section>}
    {!scan ? (history.length > 0 || scanBusy) && <section className="panel empty">
      <span className="empty-icon"><ScanSearch size={22} /></span>
      <h2>{scanBusy ? "Loading completed scans…" : "No scan selected"}</h2>
      <p>{history.length ? "Select a completed scan to review its evidence." : "Choose a folder or file above and run your first scan."}</p>
    </section> : <div className="review-columns">
      <div className="review-main">
        <section className="panel" aria-labelledby="review-answer-heading">
          <div className="panel-head"><h2 id="review-answer-heading">Scan evidence</h2></div>
          <div className="panel-body review-answer" aria-live="polite" aria-busy={busy || undefined}>
            {turn ? <>
              <p className="review-current-question">{turn.question}</p>
              <div className="review-answer-text">
                {turn.result.answer.split("\n").filter(line => line.trim()).map((line, index) => <p key={index}>{line}</p>)}
              </div>
              {!!turn.result.references.length && <div className="review-references">
                <h3>Finding references</h3>
                <ol>
                  {turn.result.references.map((reference, index) => {
                    const finding = referencedFinding(scan, reference);
                    const location = reference.line > 0 ? `${reference.path}:${reference.line}` : reference.path;
                    const label = <><FileCode2 size={16} /><span><strong>{reference.rule}</strong><code>{location}</code></span></>;
                    return <li key={`${reference.index}-${index}`}>
                      {finding ? <button className="review-reference" onClick={() => openFinding(finding)}>{label}<ChevronRight size={16} /></button> :
                        <div className="review-reference">{label}</div>}
                    </li>;
                  })}
                </ol>
              </div>}
            </> : <p>{busy ? "Looking up evidence for this question." : "Look up a file or rule to see matching findings and their source references."}</p>}
          </div>
        </section>
        <section className="panel composer">
          <form className="panel-body review-form" onSubmit={event => void submit(event)}>
            <label htmlFor="review-question">Ask about saved evidence</label>
            <p className="review-method" id="review-question-hint">Search this scan locally by file, rule, CWE, or severity.</p>
            <textarea id="review-question" rows={3} maxLength={500} value={draft} disabled={busy}
              aria-describedby="review-question-hint"
              placeholder="Find observations related to CWE-89"
              onChange={event => {
                const question = event.target.value;
                setDrafts(previous => ({ ...previous, [scanId]: question }));
              }} />
            <div className="review-submit">
              
              <button className="button primary" disabled={!native || scanBusy || busy || !draft.trim()}>
                {busy ? "Looking up evidence…" : "Look up evidence"} <ArrowRight size={16} />
              </button>
            </div>
            {busy && <p className="status-message" role="status">Reading the saved scan…</p>}
            {errors[scanId] && <p className="status-message error-text" role="alert">{errors[scanId]}</p>}
            {storageError && <p className="status-message" role="status">Review history is available until this window closes.</p>}
          </form>
        </section>
      </div>
      <div className="review-side">
        <section className="saved-inspector"><div className="inspector-title"><FileCode2 size={19}/><h2>Saved evidence</h2></div>
          {preview ? <><code>{preview.path}{preview.line > 0 && `:${preview.line}`}</code><h3>{preview.id}</h3>
            {(preview.source_line ?? preview.source_context) && <pre>{preview.source_line ?? preview.source_context}</pre>}
            <button className="button" onClick={() => openFinding(preview)}>Open code view <ChevronRight size={15}/></button></> :
            <p>{turn ? "No source reference for this lookup." : "No saved findings in this scan."}</p>}</section>
        {!!turn?.result.events.length && <section className="panel" aria-labelledby="review-timeline-heading">
          <div className="panel-head"><h2 id="review-timeline-heading">Tool timeline</h2><button className="text-button" onClick={openLog}><ListChecks size={15} /> Activity log</button></div>
          <ol className="review-timeline">
            {turn.result.events.map((event, index) => <li key={`${event.tool}-${index}`}>
              <span className="review-event-mark" aria-hidden="true" />
              <div className="review-event">
                <strong>{event.tool.replaceAll("_", " ")}</strong>
                <span className="review-event-meta">{event.status.replaceAll("_", " ")} · {event.duration_ms} ms</span>
                <p>{event.summary}</p>
              </div>
            </li>)}
          </ol>
        </section>}
        {turns.length > 0 && <section className="panel" aria-labelledby="review-history-heading">
          <div className="panel-head"><h2 id="review-history-heading">Recent questions</h2></div>
          <ul className="review-history">
            {turns.map(({ question }, index) => <li key={`${index}-${question}`}>
              <button aria-pressed={selectedTurn === index}
                onClick={() => setSelectedTurns(previous => ({ ...previous, [scanId]: index }))}>{question}</button>
            </li>)}
          </ul>
        </section>}
      </div>
    </div>}
  </div>;
}
