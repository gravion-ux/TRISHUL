import type { ScanLog } from "../types";

interface LogStreamProps {
  logs: ScanLog[];
}

function formatTime(timestamp: string): string {
  const parsed = Date.parse(timestamp);
  if (Number.isNaN(parsed)) {
    return timestamp;
  }
  return new Date(parsed).toLocaleTimeString();
}

export default function LogStream({ logs }: LogStreamProps) {
  const recent = logs.slice(-200);

  return (
    <section className="panel log-panel">
      <header className="panel-head">
        <h2>Scan log</h2>
        <span className="muted">{logs.length} events</span>
      </header>

      <div className="log-stream" role="log" aria-live="polite" aria-label="Scan log output">
        {recent.length === 0 ? (
          <p className="muted">No log output yet.</p>
        ) : (
          recent.map((log, index) => (
            <div className="log-row" key={`${log.timestamp}-${index}`}>
              <span className="mono log-time">{formatTime(log.timestamp)}</span>
              <span className="badge badge-quiet log-stage">{log.stage || log.type}</span>
              <span className="log-message">{log.message}</span>
              {typeof log.percent === "number" ? (
                <span className="mono log-percent">{Math.round(log.percent)}%</span>
              ) : null}
            </div>
          ))
        )}
      </div>
    </section>
  );
}
