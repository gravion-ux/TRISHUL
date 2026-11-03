import { useEffect, useState } from "react";
import {
  createIntegration,
  deleteIntegration,
  invokeIntegration,
  listIntegrations,
  testIntegration,
} from "../api";
import type {
  IntegrationConfig,
  IntegrationConfigRequest,
  IntegrationTestResult,
  InvokeIntegrationResponse,
} from "../types";

interface IntegrationForm {
  name: string;
  base_url: string;
  path: string;
  method: "GET" | "POST";
  auth_type: "none" | "bearer" | "header" | "query";
  auth_name: string;
  api_key: string;
  headers: string;
  params: string;
  response_json_path: string;
  enabled: boolean;
  rate_limit_per_minute: number;
  cache_ttl_seconds: number;
}

const EMPTY_FORM: IntegrationForm = {
  name: "",
  base_url: "",
  path: "",
  method: "GET",
  auth_type: "none",
  auth_name: "",
  api_key: "",
  headers: "{}",
  params: "{}",
  response_json_path: "",
  enabled: true,
  rate_limit_per_minute: 60,
  cache_ttl_seconds: 300,
};

interface ActionState {
  name: string;
  kind: "test" | "invoke";
  test?: IntegrationTestResult;
  invoke?: InvokeIntegrationResponse;
  error?: string;
  busy: boolean;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

function parseRecord(raw: string, label: string): Record<string, string> {
  if (raw.trim() === "") {
    return {};
  }
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    result[key] = typeof value === "string" ? value : JSON.stringify(value);
  }
  return result;
}

function parseParams(raw: string): Record<string, unknown> {
  if (raw.trim() === "") {
    return {};
  }
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Parameters must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

export default function IntegrationsPanel() {
  const [integrations, setIntegrations] = useState<IntegrationConfig[]>([]);
  const [form, setForm] = useState<IntegrationForm>(EMPTY_FORM);
  const [paramsInput, setParamsInput] = useState("{}");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [action, setAction] = useState<ActionState | null>(null);

  const refresh = async (): Promise<void> => {
    setLoading(true);
    try {
      setIntegrations(await listIntegrations());
      setError(null);
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listIntegrations()
      .then((items) => {
        if (!cancelled) {
          setIntegrations(items);
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setError(describe(cause));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const update = <K extends keyof IntegrationForm>(key: K, value: IntegrationForm[K]): void => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const handleCreate = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const payload: IntegrationConfigRequest = {
        name: form.name.trim(),
        base_url: form.base_url.trim(),
        path: form.path.trim(),
        method: form.method,
        auth_type: form.auth_type,
        auth_name: form.auth_name.trim(),
        headers: parseRecord(form.headers, "Headers"),
        params: parseRecord(form.params, "Params"),
        response_json_path: form.response_json_path.trim(),
        enabled: form.enabled,
        rate_limit_per_minute: Number(form.rate_limit_per_minute),
        cache_ttl_seconds: Number(form.cache_ttl_seconds),
      };
      if (form.api_key.trim()) {
        payload.api_key = form.api_key.trim();
      }
      await createIntegration(payload);
      setForm(EMPTY_FORM);
      setMessage(`Integration "${payload.name}" created.`);
      await refresh();
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (name: string): Promise<void> => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await deleteIntegration(name);
      setMessage(`Integration "${name}" deleted.`);
      await refresh();
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  const handleTest = async (name: string): Promise<void> => {
    setAction({ name, kind: "test", busy: true });
    setError(null);
    try {
      const params = parseParams(paramsInput);
      const result = await testIntegration(name, { params });
      setAction({ name, kind: "test", test: result, busy: false });
    } catch (cause) {
      setAction({ name, kind: "test", error: describe(cause), busy: false });
    }
  };

  const handleInvoke = async (name: string): Promise<void> => {
    setAction({ name, kind: "invoke", busy: true });
    setError(null);
    try {
      const params = parseParams(paramsInput);
      const result = await invokeIntegration(name, params);
      setAction({ name, kind: "invoke", invoke: result, busy: false });
    } catch (cause) {
      setAction({ name, kind: "invoke", error: describe(cause), busy: false });
    }
  };

  return (
    <section className="panel integrations-panel">
      <header className="panel-head">
        <h2>External API integrations</h2>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
          Refresh
        </button>
      </header>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
      {message ? <p className="form-success">{message}</p> : null}

      <div className="field">
        <label htmlFor="integration-params">Invocation parameters (JSON)</label>
        <textarea
          id="integration-params"
          name="params"
          rows={3}
          value={paramsInput}
          onChange={(event) => setParamsInput(event.target.value)}
        />
        <small className="muted">Used by both Test and Invoke.</small>
      </div>

      {loading ? <p className="muted">Loading integrations…</p> : null}

      {!loading && integrations.length === 0 ? (
        <p className="muted">No integrations configured yet.</p>
      ) : null}

      <div className="integration-list">
        {integrations.map((integration) => (
          <article className="integration-card" key={integration.name}>
            <header className="integration-head">
              <div>
                <h3>{integration.name}</h3>
                <p className="mono muted small">
                  {integration.method} {integration.base_url}
                  {integration.path}
                </p>
              </div>
              <div className="integration-badges">
                <span className="badge badge-quiet">{integration.auth_type}</span>
                {integration.enabled ? (
                  <span className="badge badge-ok">enabled</span>
                ) : (
                  <span className="badge badge-warn">disabled</span>
                )}
                {integration.has_api_key ? (
                  <span className="badge badge-quiet">key set</span>
                ) : null}
              </div>
            </header>

            <dl className="kv compact">
              <div>
                <dt>Rate limit</dt>
                <dd>{integration.rate_limit_per_minute}/min</dd>
              </div>
              <div>
                <dt>Cache TTL</dt>
                <dd>{integration.cache_ttl_seconds}s</dd>
              </div>
              <div>
                <dt>Response path</dt>
                <dd className="mono">{integration.response_json_path || "whole body"}</dd>
              </div>
            </dl>

            <div className="actions">
              <button
                type="button"
                className="btn btn-sm"
                disabled={action?.busy === true}
                onClick={() => void handleTest(integration.name)}
              >
                {action?.name === integration.name && action.kind === "test" && action.busy
                  ? "Testing…"
                  : "Test"}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                disabled={action?.busy === true}
                onClick={() => void handleInvoke(integration.name)}
              >
                {action?.name === integration.name && action.kind === "invoke" && action.busy
                  ? "Invoking…"
                  : "Invoke"}
              </button>
              <button
                type="button"
                className="btn btn-sm btn-danger"
                disabled={busy}
                onClick={() => void handleDelete(integration.name)}
              >
                Delete
              </button>
            </div>

            {action && action.name === integration.name ? (
              <div className="integration-result">
                {action.error ? (
                  <p className="form-error" role="alert">
                    {action.error}
                  </p>
                ) : null}

                {action.test ? (
                  <>
                    <p className="muted small">
                      Status {action.test.status_code} · {action.test.latency_ms} ms ·{" "}
                      {action.test.ok ? "ok" : "failed"}
                    </p>
                    <p className="muted small">{action.test.message}</p>
                    {action.test.preview ? (
                      <pre className="code-block">{JSON.stringify(action.test.preview, null, 2)}</pre>
                    ) : null}
                  </>
                ) : null}

                {action.invoke ? (
                  <>
                    <p className="muted small">
                      {action.invoke.ok ? "ok" : "failed"} · {action.invoke.latency_ms} ms ·{" "}
                      {action.invoke.cached ? "cached" : "live"}
                    </p>
                    <pre className="code-block">
                      {JSON.stringify(action.invoke.data, null, 2)}
                    </pre>
                  </>
                ) : null}
              </div>
            ) : null}
          </article>
        ))}
      </div>

      <div className="subsection">
        <h3>Add integration</h3>
        <div className="grid-2">
          <div className="field">
            <label htmlFor="integration-name">Name</label>
            <input
              id="integration-name"
              name="name"
              type="text"
              value={form.name}
              onChange={(event) => update("name", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-base-url">Base URL</label>
            <input
              id="integration-base-url"
              name="base_url"
              type="text"
              value={form.base_url}
              onChange={(event) => update("base_url", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-path">Path</label>
            <input
              id="integration-path"
              name="path"
              type="text"
              placeholder="/v1/items"
              value={form.path}
              onChange={(event) => update("path", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-method">Method</label>
            <select
              id="integration-method"
              name="method"
              value={form.method}
              onChange={(event) => update("method", event.target.value as "GET" | "POST")}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>

          <div className="field">
            <label htmlFor="integration-auth-type">Auth type</label>
            <select
              id="integration-auth-type"
              name="auth_type"
              value={form.auth_type}
              onChange={(event) =>
                update("auth_type", event.target.value as IntegrationForm["auth_type"])
              }
            >
              <option value="none">none</option>
              <option value="bearer">bearer</option>
              <option value="header">header</option>
              <option value="query">query</option>
            </select>
          </div>

          <div className="field">
            <label htmlFor="integration-auth-name">Auth name (header / query param)</label>
            <input
              id="integration-auth-name"
              name="auth_name"
              type="text"
              placeholder="Authorization"
              value={form.auth_name}
              onChange={(event) => update("auth_name", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-api-key">API key</label>
            <input
              id="integration-api-key"
              name="api_key"
              type="password"
              autoComplete="off"
              value={form.api_key}
              onChange={(event) => update("api_key", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-response-path">Response JSON path</label>
            <input
              id="integration-response-path"
              name="response_json_path"
              type="text"
              placeholder="data.results"
              value={form.response_json_path}
              onChange={(event) => update("response_json_path", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-headers">Headers (JSON)</label>
            <textarea
              id="integration-headers"
              name="headers"
              rows={3}
              value={form.headers}
              onChange={(event) => update("headers", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-default-params">Params (JSON)</label>
            <textarea
              id="integration-default-params"
              name="params"
              rows={3}
              value={form.params}
              onChange={(event) => update("params", event.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-rate-limit">Rate limit (per minute)</label>
            <input
              id="integration-rate-limit"
              name="rate_limit_per_minute"
              type="number"
              min={1}
              value={form.rate_limit_per_minute}
              onChange={(event) => update("rate_limit_per_minute", Number(event.target.value))}
            />
          </div>

          <div className="field">
            <label htmlFor="integration-cache-ttl">Cache TTL (seconds)</label>
            <input
              id="integration-cache-ttl"
              name="cache_ttl_seconds"
              type="number"
              min={0}
              value={form.cache_ttl_seconds}
              onChange={(event) => update("cache_ttl_seconds", Number(event.target.value))}
            />
          </div>
        </div>

        <div className="checkbox field">
          <input
            id="integration-enabled"
            name="enabled"
            type="checkbox"
            checked={form.enabled}
            onChange={(event) => update("enabled", event.target.checked)}
          />
          <label htmlFor="integration-enabled">Enabled</label>
        </div>

        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() => void handleCreate()}
        >
          {busy ? "Working…" : "Create integration"}
        </button>
      </div>
    </section>
  );
}
