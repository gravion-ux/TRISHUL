import { useState, type FormEvent } from "react";
import { TRISHUL_ASCII } from "./Sidebar";

interface LoginPanelProps {
  onLogin: (username: string, password: string) => Promise<void>;
  error: string | null;
  busy: boolean;
}

export default function LoginPanel({ onLogin, error, busy }: LoginPanelProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    await onLogin(username, password);
  };

  return (
    <div className="login-shell">
      <form className="panel login-card" onSubmit={handleSubmit}>
        <pre className="ascii-banner" aria-hidden="true">
          {TRISHUL_ASCII}
        </pre>
        <h1>TRISHUL</h1>
        <p className="muted">
          Authorized-scope AI security testing console. Sign in with the credentials configured
          on the backend.
        </p>

        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}

        <div className="field">
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
        </div>

        <div className="field">
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </div>

        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
