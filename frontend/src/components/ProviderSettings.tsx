import { useEffect, useState } from "react";
import {
  getCurrentProvider,
  getModels,
  getProviders,
  resetProviderConfig,
  saveProviderConfig,
  testProvider,
} from "../api";
import type {
  ProviderConfig,
  ProviderConfigRequest,
  ProviderDescriptor,
  ProviderKind,
  ProviderTestRequest,
  ProviderTestResult,
} from "../types";

type BusyAction = "save" | "test" | "models" | "reset" | null;

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

export default function ProviderSettings() {
  const [descriptors, setDescriptors] = useState<ProviderDescriptor[]>([]);
  const [current, setCurrent] = useState<ProviderConfig | null>(null);
  const [provider, setProvider] = useState<ProviderKind | "">("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);
  const [busy, setBusy] = useState<BusyAction>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([getProviders(), getCurrentProvider()])
      .then(([providerList, config]) => {
        if (cancelled) {
          return;
        }
        setDescriptors(providerList);
        setCurrent(config);
        setProvider(config.provider);
        setModel(config.model);
        setBaseUrl(config.base_url);
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

  const descriptor = descriptors.find((item) => item.kind === provider);

  const handleProviderChange = (kind: ProviderKind): void => {
    setProvider(kind);
    setModels([]);
    setTestResult(null);
    const match = descriptors.find((item) => item.kind === kind);
    if (match) {
      setBaseUrl(match.default_base_url);
      setModel(match.default_model);
    }
  };

  const handleSave = async (): Promise<void> => {
    if (!provider) {
      setError("Select a provider first.");
      return;
    }
    setBusy("save");
    setError(null);
    setMessage(null);
    try {
      const payload: ProviderConfigRequest = {
        provider,
        model: model.trim(),
        base_url: baseUrl.trim(),
      };
      if (apiKey.trim()) {
        payload.api_key = apiKey.trim();
      }
      const saved = await saveProviderConfig(payload);
      setCurrent(saved);
      setApiKey("");
      setMessage("Provider configuration saved.");
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(null);
    }
  };

  const handleTest = async (): Promise<void> => {
    setBusy("test");
    setError(null);
    setMessage(null);
    try {
      const payload: ProviderTestRequest = {};
      if (provider) {
        payload.provider = provider;
      }
      if (model.trim()) {
        payload.model = model.trim();
      }
      if (baseUrl.trim()) {
        payload.base_url = baseUrl.trim();
      }
      if (apiKey.trim()) {
        payload.api_key = apiKey.trim();
      }
      const result = await testProvider(payload);
      setTestResult(result);
      setMessage(result.ok ? "Provider reachable." : "Provider test failed.");
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(null);
    }
  };

  const handleDiscover = async (): Promise<void> => {
    setBusy("models");
    setError(null);
    setMessage(null);
    try {
      const result = await getModels(provider || undefined, baseUrl.trim() || undefined);
      setModels(result.models);
      setMessage(`${result.models.length} model(s) discovered.`);
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(null);
    }
  };

  const handleReset = async (): Promise<void> => {
    setBusy("reset");
    setError(null);
    setMessage(null);
    try {
      const reset = await resetProviderConfig();
      setCurrent(reset);
      setProvider(reset.provider);
      setModel(reset.model);
      setBaseUrl(reset.base_url);
      setApiKey("");
      setModels([]);
      setTestResult(null);
      setMessage("Provider configuration reset to the edition default.");
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel provider-panel">
      <header className="panel-head">
        <h2>AI provider</h2>
        <span className="muted">{current ? current.edition.toUpperCase() : "—"}</span>
      </header>

      {loading ? <p className="muted">Loading provider configuration…</p> : null}

      {current ? (
        <dl className="kv">
          <div>
            <dt>Active provider</dt>
            <dd>{current.provider}</dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd>{current.model || "—"}</dd>
          </div>
          <div>
            <dt>Base URL</dt>
            <dd className="mono">{current.base_url || "—"}</dd>
          </div>
          <div>
            <dt>Stored API key</dt>
            <dd className="mono">
              {current.has_api_key ? current.api_key_hint || "configured" : "not set"}
            </dd>
          </div>
          <div>
            <dt>Timeout</dt>
            <dd>{current.timeout_seconds}s</dd>
          </div>
          <div>
            <dt>Updated</dt>
            <dd>{current.updated_at ?? "never"}</dd>
          </div>
        </dl>
      ) : null}

      <div className="grid-2">
        <div className="field">
          <label htmlFor="provider-kind">Provider</label>
          <select
            id="provider-kind"
            name="provider"
            value={provider}
            onChange={(event) => handleProviderChange(event.target.value as ProviderKind)}
          >
            <option value="">Select a provider…</option>
            {descriptors.map((item) => (
              <option key={item.kind} value={item.kind}>
                {item.label} ({item.edition})
              </option>
            ))}
          </select>
          {descriptor ? <small className="muted">{descriptor.notes}</small> : null}
        </div>

        <div className="field">
          <label htmlFor="provider-model">Model</label>
          <input
            id="provider-model"
            name="model"
            list="provider-model-options"
            type="text"
            value={model}
            onChange={(event) => setModel(event.target.value)}
          />
          <datalist id="provider-model-options">
            {models.map((item) => (
              <option key={item} value={item} />
            ))}
          </datalist>
          {descriptor?.supports_models_discovery ? (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={busy !== null}
              onClick={() => {
                void handleDiscover();
              }}
            >
              {busy === "models" ? "Discovering…" : "Discover models"}
            </button>
          ) : null}
        </div>

        <div className="field">
          <label htmlFor="provider-base-url">Base URL</label>
          <input
            id="provider-base-url"
            name="base_url"
            type="text"
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
          />
        </div>

        <div className="field">
          <label htmlFor="provider-api-key">API key</label>
          <input
            id="provider-api-key"
            name="api_key"
            type="password"
            autoComplete="off"
            placeholder="Leave blank to keep the stored key"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
          />
          <small className="muted">Stored keys are never returned — only the hint above.</small>
        </div>
      </div>

      <div className="actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy !== null || !provider}
          onClick={() => {
            void handleSave();
          }}
        >
          {busy === "save" ? "Saving…" : "Save configuration"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy !== null}
          onClick={() => {
            void handleTest();
          }}
        >
          {busy === "test" ? "Testing…" : "Test provider"}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy !== null}
          onClick={() => {
            void handleReset();
          }}
        >
          {busy === "reset" ? "Resetting…" : "Reset to default"}
        </button>
      </div>

      {message ? <p className="form-success">{message}</p> : null}
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      {testResult ? (
        <div className="subsection">
          <h4>Test result</h4>
          <dl className="kv">
            <div>
              <dt>Reachable</dt>
              <dd>{testResult.ok ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>Latency</dt>
              <dd>{testResult.latency_ms} ms</dd>
            </div>
            <div>
              <dt>Message</dt>
              <dd>{testResult.message || "—"}</dd>
            </div>
          </dl>
          {testResult.models.length > 0 ? (
            <p className="muted small">Models: {testResult.models.join(", ")}</p>
          ) : null}
        </div>
      ) : null}

      {models.length > 0 ? (
        <div className="subsection">
          <h4>Discovered models</h4>
          <div className="model-list">
            {models.map((item) => (
              <button
                key={item}
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => setModel(item)}
              >
                {item}
              </button>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
