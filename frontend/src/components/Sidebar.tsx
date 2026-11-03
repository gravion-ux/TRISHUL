import { useState } from "react";
import type { HealthResponse, ProviderEdition } from "../types";

export const TRISHUL_ASCII = `██████╗ ██████╗ ██╗███████╗██╗  ██╗██╗   ██╗██╗
██╔══██╗██╔══██╗██║██╔════╝██║  ██║██║   ██║██║
██████╔╝██████╔╝██║█████╗  ███████║██║   ██║██║
██╔═══╝ ██╔══██╗██║██╔══╝  ██╔══██║██║   ██║██║
██║     ██║  ██║██║███████╗██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝`;

export type ViewKey = "dashboard" | "scans" | "providers" | "integrations";

interface SidebarProps {
  health: HealthResponse | null;
  edition: ProviderEdition | null;
  username: string | null;
  activeView: ViewKey;
  onNavigate: (view: ViewKey) => void;
  onLogout: () => void;
}

const NAV_ITEMS: Array<{ key: ViewKey; label: string }> = [
  { key: "dashboard", label: "Assessment" },
  { key: "scans", label: "Scan history" },
  { key: "providers", label: "AI providers" },
  { key: "integrations", label: "Integrations" },
];

export default function Sidebar({
  health,
  edition,
  username,
  activeView,
  onNavigate,
  onLogout,
}: SidebarProps) {
  const [copied, setCopied] = useState(false);
  const commands = health?.autofix_commands ?? [];

  const copyAutofix = async (): Promise<void> => {
    if (commands.length === 0) {
      return;
    }
    try {
      await navigator.clipboard.writeText(commands.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <aside className="sidebar">
      <div className="brand-block">
        <pre className="ascii-banner" aria-label="TRISHUL">
          {TRISHUL_ASCII}
        </pre>
        <p className="tagline">Authorized security testing only.</p>
        <div className="brand-badges">
          <span className="badge badge-edition">{edition ? edition.toUpperCase() : "—"}</span>
          <span className="badge badge-quiet">v{health?.version ?? "—"}</span>
        </div>
      </div>

      <nav className="nav" aria-label="Primary">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.key}
            type="button"
            className={`nav-item${activeView === item.key ? " active" : ""}`}
            aria-current={activeView === item.key ? "page" : undefined}
            onClick={() => onNavigate(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <section className="health-card" aria-label="Environment health">
        <header className="panel-head">
          <h2>Environment</h2>
          <span className={health?.ready ? "status ok" : "status warn"}>
            {health?.ready ? "ready" : "degraded"}
          </span>
        </header>

        <p className="muted small">
          {health?.ai?.configured
            ? `AI: ${health.ai.provider} / ${health.ai.model} — ${health.ai.reachable ? "reachable" : "unreachable"}`
            : "AI provider not configured"}
        </p>

        <div className="tool-grid">
          {(health?.tools ?? []).map((tool) => (
            <div
              key={tool.name}
              className={`tool-chip ${tool.installed ? "ok" : "missing"}`}
              title={tool.installed ? tool.version ?? "installed" : tool.fix_command ?? "missing"}
            >
              <span>{tool.name}</span>
              <small>{tool.installed ? "installed" : "missing"}</small>
            </div>
          ))}
        </div>

        {commands.length > 0 ? (
          <div className="autofix-block">
            <div className="panel-head">
              <h3>Autofix</h3>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  void copyAutofix();
                }}
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="autofix-commands">{commands.join("\n")}</pre>
          </div>
        ) : null}
      </section>

      <div className="sidebar-footer">
        <span className="muted small">{username ? `Signed in as ${username}` : "Not signed in"}</span>
        <button type="button" className="btn btn-ghost btn-sm" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </aside>
  );
}
