import type { Finding, Severity } from "../types";

interface FindingsListProps {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (finding: Finding) => void;
  onStartGuide: (finding: Finding) => void;
}

const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];

function severityClass(severity: Severity): string {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "low";
    case "Informational":
      return "info";
  }
}

export default function FindingsList({
  findings,
  selectedId,
  onSelect,
  onStartGuide,
}: FindingsListProps) {
  const groups = SEVERITY_ORDER.map((severity) => ({
    severity,
    items: findings.filter((finding) => finding.severity === severity),
  })).filter((group) => group.items.length > 0);

  return (
    <section className="panel findings-panel">
      <header className="panel-head">
        <h2>Findings</h2>
        <span className="muted">{findings.length} total</span>
      </header>

      {findings.length === 0 ? (
        <p className="muted">No findings recorded yet.</p>
      ) : (
        groups.map((group) => (
          <div className="finding-group" key={group.severity}>
            <h3 className="group-title">
              <span className={`severity ${severityClass(group.severity)}`}>{group.severity}</span>
              <span className="muted small">{group.items.length}</span>
            </h3>

            <div className="finding-grid">
              {group.items.map((finding) => (
                <article
                  className={`finding-card${finding.id === selectedId ? " selected" : ""}`}
                  key={finding.id}
                >
                  <div className="finding-head">
                    <span className={`severity ${severityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    {finding.verified ? <span className="badge badge-ok">verified</span> : null}
                    {finding.ai_adjusted ? <span className="badge badge-warn">AI adjusted</span> : null}
                  </div>

                  <h4>{finding.title}</h4>
                  <p className="muted small">{finding.description}</p>

                  <dl className="kv compact">
                    <div>
                      <dt>Confidence</dt>
                      <dd>{Math.round(finding.confidence)}</dd>
                    </div>
                    <div>
                      <dt>Baseline</dt>
                      <dd>{Math.round(finding.baseline_confidence)}</dd>
                    </div>
                    <div>
                      <dt>Asset</dt>
                      <dd className="mono">{finding.asset || "—"}</dd>
                    </div>
                  </dl>

                  {finding.ai_analysis ? (
                    <p className="ai-analysis">{finding.ai_analysis}</p>
                  ) : null}

                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => onSelect(finding)}
                    >
                      Details
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm btn-ghost"
                      onClick={() => onStartGuide(finding)}
                    >
                      Guide me
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </div>
        ))
      )}
    </section>
  );
}
