import { useEffect, useState } from "react";
import { Activity, ChevronRight } from "lucide-react";
import { type Scan } from "./model";

export type LogEvent = { title: string; detail: string; tool?: string; duration?: number; finding?: number; splitCounts?: boolean };
export type RecordEvent = (scanId: string, event: LogEvent) => void;
type Entry = LogEvent & { id: string; scanId: string; time: string };
const key = "helinity.desktop.activity.v1";

export function useActivityLog() {
  const [entries, setEntries] = useState<Entry[]>(() => {
    try {
      const data = JSON.parse(localStorage.getItem(key) || "[]");
      return Array.isArray(data) ? data.filter(e => typeof e?.id === "string" && typeof e.time === "string" && typeof e.title === "string" && typeof e.detail === "string").slice(0, 250) : [];
    } catch { return []; }
  });
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(entries)); } catch { /* In-memory history remains available. */ } }, [entries]);
  const record: RecordEvent = (scanId, event) => {
    const entry = { ...event, splitCounts: true, scanId, id: crypto.randomUUID(), time: new Date().toISOString() };
    setEntries(previous => [entry, ...previous].slice(0, 250));
  };
  return { entries, record };
}

export function ActivityLog({ scan, entries, open }: { scan: Scan | null; entries: Entry[]; open: (index: number) => void }) {
  const [selected, select] = useState("");
  const items = entries.filter(entry => entry.scanId === scan?.id);
  const active = items.find(entry => entry.id === selected) ?? items[0];
  return <div className="ledger"><section className="ledger-list"><h2>Review timeline</h2>
    {items.length ? <ol>{items.map(entry => <li key={entry.id}><button aria-pressed={entry.id === active?.id} onClick={() => select(entry.id)}>
      <time dateTime={entry.time}>{new Date(entry.time).toLocaleTimeString("en-GB")}</time><span>{entry.title}</span><ChevronRight size={16}/></button></li>)}</ol> :
      <p>No activity yet. Scan a project or look up saved evidence to record an event.</p>}</section>
    {active && <aside className="ledger-detail"><Activity size={22}/><h2>{active.title}</h2><p>{active.title === "Scan completed" && scan ? `${scan.files.length} files · ${scan.findings.length} findings · ${scan.warnings.length} analysis warnings` : active.detail}</p>
      <dl><dt>Recorded</dt><dd>{new Date(active.time).toLocaleString("en-GB")}</dd>{active.tool && <><dt>Tool</dt><dd>{active.tool}</dd></>}
      {active.duration !== undefined && <><dt>Duration</dt><dd>{active.duration} ms</dd></>}<dt>Scan ID</dt><dd>{active.scanId}</dd></dl>
      {active.finding !== undefined && scan?.findings[active.finding] && (active.splitCounts || !scan.warnings.length) && <button className="button" onClick={() => open(active.finding!)}>Open evidence <ChevronRight size={15}/></button>}</aside>}</div>;
}
