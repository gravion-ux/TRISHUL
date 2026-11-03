import type { ScanProgress, ScanStatus } from "../types";

interface ProgressPanelProps {
  progress: ScanProgress | null;
  status: ScanStatus | null;
  scanId: string | null;
  connected: boolean;
  canCancel: boolean;
  cancelling: boolean;
  onCancel: () => void;
  error: string | null;
}

export default function ProgressPanel({
  progress,
  status,
  scanId,
  connected,
  canCancel,
  cancelling,
  onCancel,
  error,
}: ProgressPanelProps) {
  const stage = progress?.stage ?? "idle";
  const percent = Math.max(0, Math.min(100, progress?.percent ?? 0));
  const message = progress?.message ?? "No scan running.";

  return (
    <section className="panel progress-panel">
      <header className="panel-head">
        <h2>Live progress</h2>
        <span className="status">{stage}</span>
      </header>

      <div
        className="meter"
        role="progressbar"
        aria-label="Scan progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(percent)}
        aria-valuetext={`${Math.round(percent)}% — ${stage}`}
      >
        <div className="meter-fill" style={{ width: `${percent}%` }} />
      </div>

      <div className="progress-meta">
        <strong className="percent">{Math.round(percent)}%</strong>
        <span className="muted">{message}</span>
      </div>

      <dl className="kv">
        <div>
          <dt>Scan</dt>
          <dd className="mono">{scanId ?? "—"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{status ?? "—"}</dd>
        </div>
        <div>
          <dt>Stream</dt>
          <dd>{connected ? "live" : "offline"}</dd>
        </div>
      </dl>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      <button
        type="button"
        className="btn btn-danger"
        onClick={onCancel}
        disabled={!canCancel || cancelling}
      >
        {cancelling ? "Cancelling…" : "Cancel scan"}
      </button>
    </section>
  );
}
