import type { GuideAction, GuideSession } from "../types";

interface GuidePanelProps {
  session: GuideSession | null;
  findingTitle: string | null;
  busy: boolean;
  error: string | null;
  onAction: (action: GuideAction) => void;
}

const ACTIONS: Array<{ action: GuideAction; label: string; hint: string }> = [
  { action: "next", label: "Next", hint: "Advance to the following step" },
  { action: "done", label: "Done", hint: "Mark the current step as complete" },
  { action: "hint", label: "Hint", hint: "Show the hint for the current step" },
  { action: "retry", label: "Retry", hint: "Repeat the current step" },
];

export default function GuidePanel({
  session,
  findingTitle,
  busy,
  error,
  onAction,
}: GuidePanelProps) {
  if (!session) {
    return (
      <section className="panel guide-panel">
        <header className="panel-head">
          <h2>Guide engine</h2>
          <span className="muted">idle</span>
        </header>
        <p className="muted">
          Start a guide from a finding card to walk through manual validation step by step.
        </p>
      </section>
    );
  }

  const steps = session.steps ?? [];
  const index = Math.min(Math.max(session.current_step, 0), Math.max(steps.length - 1, 0));
  const current = steps[index];

  return (
    <section className="panel guide-panel">
      <header className="panel-head">
        <h2>Guide engine</h2>
        <span className="status">{session.status}</span>
      </header>

      {findingTitle ? <p className="muted small">Guiding: {findingTitle}</p> : null}

      {current ? (
        <div className="guide-current">
          <span className="badge badge-quiet">
            Step {index + 1} of {steps.length}
          </span>
          <p className="guide-instruction">{current.instruction}</p>
          <p className="guide-hint muted small">
            <strong>Hint:</strong> {current.hint || "No hint available."}
          </p>
        </div>
      ) : (
        <p className="muted">This guide has no steps.</p>
      )}

      <ol className="guide-steps">
        {steps.map((step) => (
          <li key={step.index} className={step.status}>
            <span className="step-index mono">{step.index + 1}</span>
            <span className="step-body">
              <strong>{step.instruction}</strong>
              <small className="muted">{step.hint}</small>
            </span>
            <span className="badge badge-quiet">{step.status}</span>
          </li>
        ))}
      </ol>

      <div className="actions">
        {ACTIONS.map((item) => (
          <button
            key={item.action}
            type="button"
            className="btn btn-sm"
            title={item.hint}
            disabled={busy}
            onClick={() => onAction(item.action)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      <div className="subsection">
        <h4>History</h4>
        {session.history.length === 0 ? (
          <p className="muted">No actions recorded yet.</p>
        ) : (
          <ul className="history-list">
            {session.history.map((entry, index) => (
              <li key={index}>{entry}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
