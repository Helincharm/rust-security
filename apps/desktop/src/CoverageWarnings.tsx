import type { Finding } from "./model";

export interface CoverageWarningsProps {
  warnings: Finding[];
}

export function CoverageWarnings({ warnings }: CoverageWarningsProps) {
  if (!warnings || warnings.length === 0) return null;

  const count = warnings.length;
  const label = `${count} analysis ${count === 1 ? "warning" : "warnings"}`;

  return (
    <details className="coverage-warnings">
      <summary>
        <span role="img" aria-hidden="true">⚠</span> {label}{" "}
        <span className="muted">· Partial coverage</span>
      </summary>
      <p>
        The analyzer could not fully check the{" "}
        {count === 1 ? "file below" : "files below"}.
      </p>
      <ul>
        {warnings.map((w, i) => {
          const path = w.path;
          const explanation = w.explanation;
          return (
            <li key={`${path}:${i}`}>
              <code>{path}</code>
              {explanation ? <>: {explanation}</> : null}
            </li>
          );
        })}
      </ul>
    </details>
  );
}

export default CoverageWarnings;