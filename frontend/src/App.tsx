import { useCallback, useEffect, useMemo, useState } from "react";
import {
  cancelScan,
  clearToken,
  getHealth,
  getMe,
  getScan,
  getToken,
  guideAction,
  listScans,
  login,
  startGuide,
  startScan,
  UNAUTHORIZED_EVENT,
} from "./api";
import { useScanSocket } from "./hooks/useScanSocket";
import { useAsync } from "./hooks/useAsync";
import ChatPanel from "./components/ChatPanel";
import FindingDetail from "./components/FindingDetail";
import FindingsList from "./components/FindingsList";
import GuidePanel from "./components/GuidePanel";
import IntegrationsPanel from "./components/IntegrationsPanel";
import LogStream from "./components/LogStream";
import LoginPanel from "./components/LoginPanel";
import ProgressPanel from "./components/ProgressPanel";
import ProviderSettings from "./components/ProviderSettings";
import ReportsPanel from "./components/ReportsPanel";
import ScanLauncher from "./components/ScanLauncher";
import Sidebar, { type ViewKey } from "./components/Sidebar";
import type {
  Finding,
  GuideAction,
  GuideSession,
  HealthResponse,
  MeResponse,
  ScanEvent,
  ScanLog,
  ScanRecord,
  ScanRequest,
} from "./types";

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

function mergeFinding(findings: Finding[], incoming: Finding): Finding[] {
  const index = findings.findIndex((item) => item.id === incoming.id);
  if (index === -1) {
    return [...findings, incoming];
  }
  const next = [...findings];
  next[index] = incoming;
  return next;
}

export default function App() {
  const [token, setToken] = useState<string | null>(() => getToken());
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);
  const [view, setView] = useState<ViewKey>("dashboard");
  const [me, setMe] = useState<MeResponse | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [guide, setGuide] = useState<GuideSession | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [guideBusy, setGuideBusy] = useState(false);
  const [guideError, setGuideError] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  /* Global 401 handling: drop the token and return to the login screen. */
  useEffect(() => {
    const handleUnauthorized = (): void => {
      setToken(null);
      setMe(null);
      setScans([]);
      setScan(null);
      setGuide(null);
      setSelectedFinding(null);
    };
    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, []);

  /* Health is public — load it before and after login. */
  const healthState = useAsync<HealthResponse>(() => getHealth(), [token]);
  const health = healthState.data;

  /* Load identity and scan history once authenticated. */
  useEffect(() => {
    if (!token) {
      setMe(null);
      setScans([]);
      return;
    }
    let cancelled = false;
    setHistoryLoading(true);
    setHistoryError(null);
    Promise.all([getMe(), listScans()])
      .then(([identity, records]) => {
        if (cancelled) {
          return;
        }
        setMe(identity);
        setScans(records);
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setHistoryError(describe(cause));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setHistoryLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  const scanActive = scan !== null && (scan.status === "queued" || scan.status === "running");

  const handleScanEvent = useCallback((event: ScanEvent): void => {
    setScan((current) => {
      if (!current) {
        if (event.type === "snapshot" || event.type === "complete") {
          return event.scan;
        }
        return current;
      }
      switch (event.type) {
        case "snapshot":
        case "complete":
          return event.scan;
        case "progress": {
          const entry: ScanLog = {
            type: "progress",
            timestamp: event.timestamp,
            stage: event.stage,
            percent: event.percent,
            message: event.message,
            payload: event.payload,
          };
          return {
            ...current,
            progress: {
              stage: event.stage,
              percent: event.percent,
              message: event.message,
            },
            logs: [...(current.logs ?? []), entry],
          };
        }
        case "finding":
          return {
            ...current,
            findings: mergeFinding(current.findings ?? [], event.finding),
          };
        case "log": {
          const entry: ScanLog = {
            type: "log",
            timestamp: event.timestamp,
            stage: event.stage,
            percent: 0,
            message: event.message,
          };
          return { ...current, logs: [...(current.logs ?? []), entry] };
        }
        case "error":
          return { ...current, status: "failed", error: event.message };
        default:
          return current;
      }
    });
  }, []);

  const socket = useScanSocket({
    scanId: token && scanActive ? scan.id : null,
    token,
    active: scanActive,
    onEvent: handleScanEvent,
  });

  const handleLogin = async (username: string, password: string): Promise<void> => {
    setLoggingIn(true);
    setLoginError(null);
    try {
      const response = await login(username, password);
      setToken(response.access_token);
      setLoginError(null);
    } catch (cause) {
      setLoginError(describe(cause));
    } finally {
      setLoggingIn(false);
    }
  };

  const handleLogout = (): void => {
    clearToken();
    setToken(null);
    setMe(null);
    setScans([]);
    setScan(null);
    setGuide(null);
    setSelectedFinding(null);
    setView("dashboard");
  };

  const handleLaunch = async (request: ScanRequest): Promise<void> => {
    setLaunching(true);
    setLaunchError(null);
    try {
      const response = await startScan(request);
      const record = await getScan(response.scan_id);
      setScan(record);
      setGuide(null);
      setSelectedFinding(null);
      setScans((current) => [record, ...current.filter((item) => item.id !== record.id)]);
    } catch (cause) {
      setLaunchError(describe(cause));
    } finally {
      setLaunching(false);
    }
  };

  const handleCancel = async (): Promise<void> => {
    if (!scan) {
      return;
    }
    setCancelling(true);
    setCancelError(null);
    try {
      const response = await cancelScan(scan.id);
      setScan((current) =>
        current
          ? { ...current, status: response.cancelled ? "cancelled" : response.status }
          : current,
      );
    } catch (cause) {
      setCancelError(describe(cause));
    } finally {
      setCancelling(false);
    }
  };

  const handleSelectScan = async (scanId: string): Promise<void> => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const record = await getScan(scanId);
      setScan(record);
      setGuide(null);
      setSelectedFinding(null);
      setView("dashboard");
    } catch (cause) {
      setHistoryError(describe(cause));
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleStartGuide = async (finding: Finding): Promise<void> => {
    if (!scan) {
      return;
    }
    setGuideBusy(true);
    setGuideError(null);
    try {
      const session = await startGuide(scan.id, finding.id);
      setGuide(session);
      setSelectedFinding(finding);
    } catch (cause) {
      setGuideError(describe(cause));
    } finally {
      setGuideBusy(false);
    }
  };

  const handleGuideAction = async (action: GuideAction): Promise<void> => {
    if (!guide) {
      return;
    }
    setGuideBusy(true);
    setGuideError(null);
    try {
      const updated = await guideAction(guide.id, action);
      setGuide(updated);
    } catch (cause) {
      setGuideError(describe(cause));
    } finally {
      setGuideBusy(false);
    }
  };

  const findings = scan?.findings ?? [];
  const logs = scan?.logs ?? [];

  const scanHistory = useMemo(
    () =>
      [...scans].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)),
    [scans],
  );

  if (!token) {
    return <LoginPanel onLogin={handleLogin} error={loginError} busy={loggingIn} />;
  }

  return (
    <div className="app-shell">
      <Sidebar
        health={health}
        edition={me?.edition ?? health?.edition ?? null}
        username={me?.username ?? null}
        activeView={view}
        onNavigate={setView}
        onLogout={handleLogout}
      />

      <main className="content">
        {view === "dashboard" ? (
          <>
            <header className="view-head">
              <div>
                <p className="eyebrow">Authorized-scope assessment console</p>
                <h1>{scan ? scan.target : "No scan loaded"}</h1>
              </div>
              {scan ? (
                <div className="view-head-meta">
                  <span className="status">{scan.status}</span>
                  {scan.ai_provider && scan.ai_provider !== "none" ? (
                    <span className="badge badge-quiet">
                      {scan.ai_provider} / {scan.ai_model}
                    </span>
                  ) : null}
                </div>
              ) : null}
            </header>

            <ScanLauncher onLaunch={handleLaunch} busy={launching} serverError={launchError} />

            <div className="grid-2">
              <ProgressPanel
                progress={scan?.progress ?? null}
                status={scan?.status ?? null}
                scanId={scan?.id ?? null}
                connected={socket.connected}
                canCancel={scanActive}
                cancelling={cancelling}
                onCancel={() => void handleCancel()}
                error={cancelError ?? (scan?.error ?? null)}
              />
              <LogStream logs={logs} />
            </div>

            <ChatPanel scanId={scan?.id ?? null} />

            <FindingsList
              findings={findings}
              selectedId={selectedFinding?.id ?? null}
              onSelect={setSelectedFinding}
              onStartGuide={(finding) => void handleStartGuide(finding)}
            />

            <div className="grid-2">
              <FindingDetail finding={selectedFinding} />
              <GuidePanel
                session={guide}
                findingTitle={selectedFinding?.title ?? null}
                busy={guideBusy}
                error={guideError}
                onAction={(action) => void handleGuideAction(action)}
              />
            </div>

            <ReportsPanel
              scanId={scan?.id ?? null}
              reportPaths={scan?.report_paths ?? {}}
              disabled={!scan}
            />
          </>
        ) : null}

        {view === "scans" ? (
          <>
            <header className="view-head">
              <div>
                <p className="eyebrow">History</p>
                <h1>Scan history</h1>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  setHistoryLoading(true);
                  setHistoryError(null);
                  listScans()
                    .then(setScans)
                    .catch((cause: unknown) => setHistoryError(describe(cause)))
                    .finally(() => setHistoryLoading(false));
                }}
              >
                Refresh
              </button>
            </header>

            {historyError ? (
              <p className="form-error" role="alert">
                {historyError}
              </p>
            ) : null}
            {historyLoading ? <p className="muted">Loading scans…</p> : null}

            {!historyLoading && scanHistory.length === 0 ? (
              <p className="muted">No scans recorded yet.</p>
            ) : null}

            <div className="scan-table">
              {scanHistory.map((record) => (
                <button
                  key={record.id}
                  type="button"
                  className={`scan-row${scan?.id === record.id ? " selected" : ""}`}
                  onClick={() => void handleSelectScan(record.id)}
                >
                  <span className="scan-row-target mono">{record.target}</span>
                  <span className="badge badge-quiet">{record.mode}</span>
                  <span className="status">{record.status}</span>
                  <span className="muted small">
                    {record.findings.length} findings ·{" "}
                    {new Date(record.created_at).toLocaleString()}
                  </span>
                </button>
              ))}
            </div>
          </>
        ) : null}

        {view === "providers" ? (
          <>
            <header className="view-head">
              <div>
                <p className="eyebrow">AI configuration</p>
                <h1>Provider settings</h1>
              </div>
            </header>
            <ProviderSettings />
          </>
        ) : null}

        {view === "integrations" ? (
          <>
            <header className="view-head">
              <div>
                <p className="eyebrow">External data sources</p>
                <h1>Integrations</h1>
              </div>
            </header>
            <IntegrationsPanel />
          </>
        ) : null}
      </main>
    </div>
  );
}
