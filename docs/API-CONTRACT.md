# TRISHUL API Contract (v1)

This file is the **binding contract** between the TRISHUL backend and the TRISHUL
frontend. Both sides are implemented against this document. Do not change a field
name or type here without changing both sides.

Base URL: `http://localhost:8000` (configurable via `VITE_API_BASE`).

## Authentication

All `/api/*` routes **except** `GET /api/health` and `POST /api/auth/token`
require a bearer token:

```
Authorization: Bearer <access_token>
```

`POST /api/auth/token` — body `{"username": string, "password": string}` →
`{"access_token": string, "token_type": "bearer", "expires_in": number}`.

Usernames/passwords come from `TRISHUL_ADMIN_USER` / `TRISHUL_ADMIN_PASSWORD`
env vars. If unset, a password is generated on first run and written to
`data/admin-credentials.txt` (mode 0600).

WebSocket auth: `ws://.../ws/scans/{scan_id}?token=<access_token>`.
If the query token is absent, fall back to the `Authorization` header (browsers
cannot set headers on WebSocket).

Error body shape for all errors: `{"detail": string}` (FastAPI standard).

## Enums

- `Severity`: `"Informational" | "Low" | "Medium" | "High" | "Critical"`
- `ScanMode`: `"quick" | "deep"`
- `ScanStatus`: `"queued" | "running" | "completed" | "failed" | "cancelled"`
- `GuideAction`: `"next" | "done" | "hint" | "retry"`
- `ProviderEdition`: `"local" | "provider"`
- `ProviderKind`: `"ollama" | "lmstudio" | "llamacpp" | "openai" | "anthropic" | "gemini" | "openai-compatible" | "custom"`

## Models (TypeScript)

```ts
type Severity = "Informational" | "Low" | "Medium" | "High" | "Critical";
type ScanMode = "quick" | "deep";
type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
type GuideAction = "next" | "done" | "hint" | "retry";
type ProviderEdition = "local" | "provider";
type ProviderKind =
  | "ollama" | "lmstudio" | "llamacpp"
  | "openai" | "anthropic" | "gemini" | "openai-compatible" | "custom";

interface Evidence {
  source: string;      // "nuclei" | "nmap" | "ffuf" | "verification" | "ai" | ...
  summary: string;
  raw: Record<string, unknown>;
}

interface PocBundle {
  steps_to_reproduce: string[];
  request_example: string;
  response_example: string;
  impact: string;
  remediation: string;
  screenshot_guide: string[];
  video_script: string[];
  bounty_report: string;
  generated_by: "ai" | "deterministic";
}

interface GuideStep {
  index: number;
  instruction: string;
  hint: string;
  status: "pending" | "active" | "completed" | "retrying";
}

interface Finding {
  id: string;
  source: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;          // 0..100 effective score
  baseline_confidence: number; // 0..100 deterministic evidence score
  ai_adjusted: boolean;
  verified: boolean;
  asset: string;
  attack_surface: string;
  evidence: Evidence[];
  references: string[];
  enrichment: Record<string, unknown>[];
  raw: Record<string, unknown>;
  poc: PocBundle | null;
  guide_steps: GuideStep[];
  ai_analysis: string;         // "" when no AI verdict was produced
}

interface ScanProgress {
  stage: string;
  percent: number;
  message: string;
}

interface ScanRecord {
  id: string;
  target: string;
  mode: ScanMode;
  status: ScanStatus;
  progress: ScanProgress;
  findings: Finding[];
  enrichment: Record<string, unknown>[];
  artifacts: Record<string, unknown>;
  logs: ScanLog[];
  report_paths: Record<string, string>;
  created_at: string;   // ISO 8601
  updated_at: string;   // ISO 8601
  authorized: boolean;
  authorization_note: string;
  error: string | null;
  ai_provider: string;  // provider kind in use, or "none"
  ai_model: string;
}

interface ScanLog {
  type: string;
  timestamp: string;
  stage: string;
  percent: number;
  message: string;
  payload?: Record<string, unknown>;
}

interface GuideSession {
  id: string;
  scan_id: string;
  finding_id: string;
  current_step: number;
  status: "active" | "completed";
  steps: GuideStep[];
  history: string[];
  updated_at: string;
}

interface ToolHealth {
  name: string;
  installed: boolean;
  path: string | null;
  version: string | null;
  fix_command: string | null;
  required: boolean;
}

interface HealthResponse {
  version: string;
  edition: ProviderEdition;
  platform: string;
  ready: boolean;
  tools: ToolHealth[];
  ai: {
    configured: boolean;
    provider: string;
    model: string;
    reachable: boolean;
    message: string;
  };
  autofix_commands: string[];
}

interface ProviderDescriptor {
  kind: ProviderKind;
  label: string;
  edition: ProviderEdition;
  default_base_url: string;
  default_model: string;
  requires_api_key: boolean;
  supports_models_discovery: boolean;
  notes: string;
}

interface ProviderConfig {
  edition: ProviderEdition;
  provider: ProviderKind;
  model: string;
  base_url: string;
  timeout_seconds: number;
  has_api_key: boolean;
  api_key_hint: string;   // e.g. "sk-...abcd" — never the full key
  updated_at: string | null;
}

interface ProviderTestResult {
  ok: boolean;
  latency_ms: number;
  message: string;
  models: string[];
}

interface ChatResponse {
  reply: string;
  provider: string;
  model: string;
  fallback: boolean;   // true when answered without an AI model
}

interface IntegrationConfig {
  name: string;
  base_url: string;
  path: string;
  method: "GET" | "POST";
  auth_type: "none" | "bearer" | "header" | "query";
  auth_name: string;      // header/query param name for bearer/header/query
  has_api_key: boolean;
  headers: Record<string, string>;
  params: Record<string, string>;
  response_json_path: string;  // dot path, "" = whole body
  enabled: boolean;
  rate_limit_per_minute: number;
  cache_ttl_seconds: number;
  created_at: string;
}

interface IntegrationTestResult {
  ok: boolean;
  status_code: number;
  latency_ms: number;
  message: string;
  preview: Record<string, unknown> | null;
}
```

## Endpoints

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| GET | `/api/health` | no | — | `HealthResponse` |
| POST | `/api/auth/token` | no | `{username, password}` | `{access_token, token_type, expires_in}` |
| GET | `/api/me` | yes | — | `{username: string, edition: ProviderEdition}` |
| GET | `/api/scans` | yes | — | `ScanRecord[]` |
| GET | `/api/scans/{scan_id}` | yes | — | `ScanRecord` |
| POST | `/api/scans` | yes | `ScanRequest` | `{scan_id, status, message}` |
| DELETE | `/api/scans/{scan_id}` | yes | — | `{scan_id, status, cancelled: boolean}` |
| GET | `/api/scans/{scan_id}/findings` | yes | — | `Finding[]` |
| POST | `/api/guides/start?scan_id=` | yes | `{finding_id}` | `GuideSession` |
| POST | `/api/guides/{guide_id}/action` | yes | `{action: GuideAction}` | `GuideSession` |
| GET | `/api/reports/{scan_id}/{fmt}` | yes | — | file download, `fmt` ∈ `json\|markdown\|html\|bug_bounty` |
| GET | `/api/providers` | yes | — | `ProviderDescriptor[]` |
| GET | `/api/providers/current` | yes | — | `ProviderConfig` |
| POST | `/api/providers/config` | yes | `ProviderConfigRequest` | `ProviderConfig` |
| POST | `/api/providers/test` | yes | `ProviderTestRequest` | `ProviderTestResult` |
| GET | `/api/providers/models?provider=&base_url=` | yes | — | `{models: string[]}` |
| DELETE | `/api/providers/config` | yes | — | `ProviderConfig` (reset to edition default) |
| POST | `/api/chat` | yes | `{message, scan_id?, history?}` | `ChatResponse` |
| GET | `/api/integrations` | yes | — | `IntegrationConfig[]` |
| POST | `/api/integrations` | yes | `IntegrationConfigRequest` | `IntegrationConfig` |
| DELETE | `/api/integrations/{name}` | yes | — | `{deleted: boolean}` |
| POST | `/api/integrations/{name}/test` | yes | `{params?: object}` | `IntegrationTestResult` |
| POST | `/api/integrations/{name}/invoke` | yes | `{params: object}` | `{ok, data, cached, latency_ms}` |
| GET | `/api/enrichment?scan_id=` | yes | — | `{scan_id, results: object[]}` |
| POST | `/api/update` | yes | — | `{success, details}` |
| GET | `/api/health/autofix` | yes | — | `{commands: string[]}` |

`ProviderConfigRequest`:
```ts
{
  edition?: ProviderEdition;   // omitted = keep current
  provider: ProviderKind;
  model?: string;
  base_url?: string;
  api_key?: string;            // optional; when omitted the stored key is kept
  timeout_seconds?: number;
}
```

`ProviderTestRequest`: `{provider?: ProviderKind, model?: string, base_url?: string, api_key?: string}`
— all optional; omitted fields fall back to the stored configuration.

`IntegrationConfigRequest`: same fields as `IntegrationConfig` except `has_api_key`,
`created_at`; `api_key` is optional and stored encrypted.

## Request models

```ts
interface ScanRequest {
  target: string;
  mode: ScanMode;
  authorized: boolean;          // must be true, else HTTP 400
  authorization_note: string;   // min length 5, else HTTP 422
  thread_limit: number;         // 1..32
  timeout_seconds: number;      // 30..7200
}
```

## WebSocket `/ws/scans/{scan_id}`

Messages sent by the server (JSON):

```ts
type ScanEvent =
  | { type: "snapshot"; scan: ScanRecord }
  | { type: "progress"; timestamp: string; stage: string; percent: number;
      message: string; payload?: Record<string, unknown> }
  | { type: "finding"; finding: Finding }
  | { type: "log"; timestamp: string; stage: string; message: string }
  | { type: "complete"; scan: ScanRecord }
  | { type: "error"; message: string };
```

Stages in order: `queued`, `recon`, `scan`, `fuzz`, `detect`, `verify`, `poc`,
`guide`, `report`, `completed` (or `failed` / `cancelled`).

## Pipeline

`Recon → Scan → Fuzz → Detect → Verify → PoC → Guide → Report`

Agents: `MasterAgent`, `ReconAgent`, `ScannerAgent`, `FuzzerAgent`,
`DetectionAgent`, `VerificationAgent`, `ReasoningEngine`, `PoCEngine`,
`GuideEngine`, `ReportAgent`.

`ReasoningEngine` runs inside the `verify` stage (it deduplicates and ranks the
verified findings) — it is not a separate pipeline stage.
