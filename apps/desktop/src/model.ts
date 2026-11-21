import { Channel, invoke, isTauri } from "@tauri-apps/api/core";

export type Finding = {
  id: string;
  tool: string;
  path: string;
  cwe: string | number | null;
  severity: string;
  confidence: string | number;
  category: string;
  verification_status?: string;
  explanation: string;
  remediation: string;
  evidence: string;
  source_context?: string | null;
  source_line?: string | null;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
};

export type Scan = {
  id: string;
  project: string;
  created_at: string;
  files: string[];
  findings: Finding[];
  warnings: Finding[];
  diagnostics: string[];
  manifests?: { path: string; name: string | null; version: string | null }[];
};

export type Summary = Omit<Scan, "files" | "findings" | "warnings" | "diagnostics" | "manifests"> & {
  files: number;
  findings: number;
  warning_count: number;
};

export type AiConfig = { provider: string; model: string; endpoint: string };
export type Progress = { files: number; path: string };
export type RuntimeInfo = Record<string, unknown>;

export const native = isTauri();
export const call = invoke;
export const severities = ["critical", "high", "medium", "low", "info"];
export const providers = [
  { id: "openai", name: "OpenAI", endpoint: "https://api.openai.com/v1", model: "" },
  { id: "anthropic", name: "Anthropic", endpoint: "https://api.anthropic.com/v1", model: "" },
  { id: "compatible", name: "OpenAI-compatible", endpoint: "", model: "" },
];

export function runScan(onProgress: (progress: Progress) => void) {
  return call<Scan | null>("scan_target", { progress: new Channel<Progress>(onProgress) });
}

export function firstConfig(): AiConfig {
  const fallback = { provider: "openai", endpoint: providers[0]!.endpoint, model: "" };
  try {
    const config = JSON.parse(localStorage.getItem("helinity.ai") || "null");
    if (providers.some(({ id }) => config?.provider === id) &&
        typeof config.endpoint === "string" && typeof config.model === "string") {
      return config;
    }
  } catch {
    // An unavailable or stale preference does not prevent local scans.
  }
  return fallback;
}

export function leaf(path: string) {
  return path.split(/[\\/]/).filter(Boolean).at(-1) || path;
}

export function severityOf(finding: Finding) {
  const value = finding.severity.toLowerCase();
  return value === "informational" ? "info" : value;
}

export function priority(a: Finding, b: Finding) {
  const getRank = (finding: Finding) => {
    const rank = severities.indexOf(severityOf(finding));
    return rank === -1 ? severities.length : rank;
  };
  return getRank(a) - getRank(b) || a.path.localeCompare(b.path) || a.line - b.line;
}

export function dateLabel(value: string) {
  const date = new Date(/^\d+$/.test(value) ? Number(value) * 1_000 : value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function findingTitle(f: Finding): string {
  const titles: Record<string, string> = {
    "HEL-RUST-001": "Formatted SQL query",
    "HEL-RUST-002": "Program selected from an environment variable",
    "HEL-RUST-003": "File read with an externally supplied path segment",
    "HEL-RUST-004": "Unchecked indexing of environment input",
  };
  return titles[f.id] ?? (f.category === "dependency" ? f.id : f.category === "coverage" ? "Incomplete analysis" : f.id);
}
