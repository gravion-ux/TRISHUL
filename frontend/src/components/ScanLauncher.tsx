import { useState, type FormEvent } from "react";
import type { ScanMode, ScanRequest } from "../types";

interface ScanLauncherProps {
  onLaunch: (request: ScanRequest) => Promise<void>;
  busy: boolean;
  serverError: string | null;
}

interface FormState {
  target: string;
  mode: ScanMode;
  authorization_note: string;
  thread_limit: number;
  timeout_seconds: number;
  authorized: boolean;
}

const INITIAL_FORM: FormState = {
  target: "",
  mode: "deep",
  authorization_note: "",
  thread_limit: 8,
  timeout_seconds: 900,
  authorized: false,
};

export default function ScanLauncher({ onLaunch, busy, serverError }: ScanLauncherProps) {
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [localError, setLocalError] = useState<string | null>(null);

  const update = <K extends keyof FormState>(key: K, value: FormState[K]): void => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const validate = (): string | null => {
    if (!form.target.trim()) {
      return "A target is required.";
    }
    if (!form.authorized) {
      return "Confirm that you are authorized to test this target before launching a scan.";
    }
    if (form.authorization_note.trim().length < 5) {
      return "The authorization note must be at least 5 characters (scope, ticket or approval).";
    }
    if (!Number.isInteger(form.thread_limit) || form.thread_limit < 1 || form.thread_limit > 32) {
      return "Threads must be an integer between 1 and 32.";
    }
    if (
      !Number.isInteger(form.timeout_seconds) ||
      form.timeout_seconds < 30 ||
      form.timeout_seconds > 7200
    ) {
      return "Timeout must be between 30 and 7200 seconds.";
    }
    return null;
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const problem = validate();
    setLocalError(problem);
    if (problem) {
      return;
    }
    await onLaunch({
      target: form.target.trim(),
      mode: form.mode,
      authorized: form.authorized,
      authorization_note: form.authorization_note.trim(),
      thread_limit: form.thread_limit,
      timeout_seconds: form.timeout_seconds,
    });
  };

  const error = localError ?? serverError;

  return (
    <section className="panel launcher">
      <header className="panel-head">
        <h2>Launch assessment</h2>
        <span className="muted">Recon → Scan → Fuzz → Detect → Verify → PoC → Guide → Report</span>
      </header>

      <form className="scan-form" onSubmit={handleSubmit} noValidate>
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}

        <div className="grid-2">
          <div className="field">
            <label htmlFor="scan-target">Target</label>
            <input
              id="scan-target"
              name="target"
              type="text"
              placeholder="example.com"
              value={form.target}
              onChange={(event) => update("target", event.target.value)}
              required
            />
          </div>

          <div className="field">
            <label htmlFor="scan-mode">Mode</label>
            <select
              id="scan-mode"
              name="mode"
              value={form.mode}
              onChange={(event) => update("mode", event.target.value as ScanMode)}
            >
              <option value="quick">Quick</option>
              <option value="deep">Deep</option>
            </select>
          </div>
        </div>

        <div className="field">
          <label htmlFor="scan-note">Authorization note</label>
          <input
            id="scan-note"
            name="authorization_note"
            type="text"
            placeholder="Bug bounty scope / ticket / approval reference"
            value={form.authorization_note}
            onChange={(event) => update("authorization_note", event.target.value)}
            required
          />
          <small className="muted">Minimum 5 characters — recorded with the scan record.</small>
        </div>

        <div className="grid-2">
          <div className="field">
            <label htmlFor="scan-threads">Threads</label>
            <input
              id="scan-threads"
              name="thread_limit"
              type="number"
              min={1}
              max={32}
              value={form.thread_limit}
              onChange={(event) => update("thread_limit", Number(event.target.value))}
            />
          </div>

          <div className="field">
            <label htmlFor="scan-timeout">Timeout (seconds)</label>
            <input
              id="scan-timeout"
              name="timeout_seconds"
              type="number"
              min={30}
              max={7200}
              value={form.timeout_seconds}
              onChange={(event) => update("timeout_seconds", Number(event.target.value))}
            />
          </div>
        </div>

        <div className="checkbox field">
          <input
            id="scan-authorized"
            name="authorized"
            type="checkbox"
            checked={form.authorized}
            onChange={(event) => update("authorized", event.target.checked)}
          />
          <label htmlFor="scan-authorized">
            I confirm I am authorized to test this target. The backend rejects unauthorized scans.
          </label>
        </div>

        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Launching…" : "Launch scan"}
        </button>
      </form>
    </section>
  );
}
