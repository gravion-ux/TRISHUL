import { useState } from "react";
import { downloadReport } from "../api";
import type { ReportFormat } from "../types";

interface ReportsPanelProps {
  scanId: string | null;
  reportPaths: Record<string, string>;
  disabled?: boolean;
}

const FORMATS: Array<{ format: ReportFormat; label: string }> = [
  { format: "json", label: "JSON" },
  { format: "markdown", label: "Markdown" },
  { format: "html", label: "HTML" },
  { format: "bug_bounty", label: "Bug bounty" },
];

export default function ReportsPanel({
  scanId,
  reportPaths,
  disabled = false,
}: ReportsPanelProps) {
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async (format: ReportFormat): Promise<void> => {
    if (!scanId) {
      return;
    }
    setBusy(format);
    setError(null);
    try {
      await downloadReport(scanId, format);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The report download failed.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel reports-panel">
      <header className="panel-head">
        <h2>Reports</h2>
        <span className="muted">{scanId ?? "no scan selected"}</span>
      </header>

      <div className="actions">
        {FORMATS.map((item) => {
          const available = reportPaths ? item.format in reportPaths : false;
          return (
            <button
              key={item.format}
              type="button"
              className="btn btn-sm"
              disabled={disabled || !scanId || busy !== null}
              title={
                available
                  ? `Download the ${item.label} report`
                  : `The ${item.label} report may not be generated yet`
              }
              onClick={() => void handleDownload(item.format)}
            >
              {busy === item.format ? "Downloading…" : `Download ${item.label}`}
            </button>
          );
        })}
      </div>

      <p className="muted small">
        Downloads are fetched with your bearer token and saved locally as a file.
      </p>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
