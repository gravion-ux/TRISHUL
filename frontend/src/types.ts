/**
 * Types derived strictly from TRISHUL docs/API-CONTRACT.md (v1).
 * Field names and types are binding — do not rename without changing the contract.
 */

export type Severity = "Informational" | "Low" | "Medium" | "High" | "Critical";
export type ScanMode = "quick" | "deep";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type GuideAction = "next" | "done" | "hint" | "retry";
export type ProviderEdition = "local" | "provider";
export type ProviderKind =
  | "ollama"
  | "lmstudio"
  | "llamacpp"
  | "openai"
  | "anthropic"
  | "gemini"
  | "openai-compatible"
  | "custom";

export interface Evidence {
  source: string;
  summary: string;
  raw: Record<string, unknown>;
}

export interface PocBundle {
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

export interface GuideStep {
  index: number;
  instruction: string;
  hint: string;
  status: "pending" | "active" | "completed" | "retrying";
}

export interface Finding {
  id: string;
  source: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  baseline_confidence: number;
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
  ai_analysis: string;
}

export interface ScanProgress {
  stage: string;
  percent: number;
  message: string;
}

export interface ScanLog {
  type: string;
  timestamp: string;
  stage: string;
  percent: number;
  message: string;
  payload?: Record<string, unknown>;
}

export interface ScanRecord {
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
  created_at: string;
  updated_at: string;
  authorized: boolean;
  authorization_note: string;
  error: string | null;
  ai_provider: string;
  ai_model: string;
  /** The concurrency limit this scan resolved to. */
  thread_limit?: number | null;
  /** The per-invocation timeout this scan resolved to, in seconds. */
  timeout_seconds?: number | null;
}

export interface GuideSession {
  id: string;
  scan_id: string;
  finding_id: string;
  current_step: number;
  status: "active" | "completed";
  steps: GuideStep[];
  history: string[];
  updated_at: string;
}

export interface ToolHealth {
  name: string;
  installed: boolean;
  path: string | null;
  version: string | null;
  fix_command: string | null;
  required: boolean;
}

export interface HealthResponse {
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

export interface ProviderDescriptor {
  kind: ProviderKind;
  label: string;
  edition: ProviderEdition;
  default_base_url: string;
  default_model: string;
  requires_api_key: boolean;
  supports_models_discovery: boolean;
  notes: string;
}

export interface ProviderConfig {
  edition: ProviderEdition;
  provider: ProviderKind;
  model: string;
  base_url: string;
  timeout_seconds: number;
  has_api_key: boolean;
  api_key_hint: string;
  updated_at: string | null;
}

export interface ProviderTestResult {
  ok: boolean;
  latency_ms: number;
  message: string;
  models: string[];
}

export interface ChatResponse {
  reply: string;
  provider: string;
  model: string;
  fallback: boolean;
}

export interface IntegrationConfig {
  name: string;
  base_url: string;
  path: string;
  method: "GET" | "POST";
  auth_type: "none" | "bearer" | "header" | "query";
  auth_name: string;
  has_api_key: boolean;
  headers: Record<string, string>;
  params: Record<string, string>;
  response_json_path: string;
  enabled: boolean;
  rate_limit_per_minute: number;
  cache_ttl_seconds: number;
  created_at: string;
}

export interface IntegrationTestResult {
  ok: boolean;
  status_code: number;
  latency_ms: number;
  message: string;
  preview: Record<string, unknown> | null;
}

/* ---------- Request / auxiliary payloads ---------- */

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface MeResponse {
  username: string;
  edition: ProviderEdition;
}

export interface ScanRequest {
  target: string;
  mode: ScanMode;
  authorized: boolean;
  authorization_note: string;
  /** 1..32. Omitted to use the configured default. */
  thread_limit?: number;
  /** 30..7200 seconds. Omitted to use the configured default. */
  timeout_seconds?: number;
}

export interface StartScanResponse {
  scan_id: string;
  status: ScanStatus;
  message: string;
}

export interface CancelScanResponse {
  scan_id: string;
  status: ScanStatus;
  cancelled: boolean;
}

export interface ProviderConfigRequest {
  edition?: ProviderEdition;
  provider: ProviderKind;
  model?: string;
  base_url?: string;
  api_key?: string;
  timeout_seconds?: number;
}

export interface ProviderTestRequest {
  provider?: ProviderKind;
  model?: string;
  base_url?: string;
  api_key?: string;
}

export interface ModelsResponse {
  models: string[];
}

export interface ChatHistoryMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ChatRequest {
  message: string;
  scan_id?: string;
  history?: ChatHistoryMessage[];
}

export interface IntegrationConfigRequest {
  name: string;
  base_url: string;
  path: string;
  method: "GET" | "POST";
  auth_type: "none" | "bearer" | "header" | "query";
  auth_name: string;
  api_key?: string;
  headers: Record<string, string>;
  params: Record<string, string>;
  response_json_path: string;
  enabled: boolean;
  rate_limit_per_minute: number;
  cache_ttl_seconds: number;
}

export interface IntegrationTestRequest {
  params?: Record<string, unknown>;
}

export interface InvokeIntegrationResponse {
  ok: boolean;
  data: Record<string, unknown> | null;
  cached: boolean;
  latency_ms: number;
}

export interface DeletedResponse {
  deleted: boolean;
}

export interface EnrichmentResponse {
  scan_id: string;
  results: Record<string, unknown>[];
}

export interface UpdateResponse {
  success: boolean;
  details: string;
}

export interface AutofixResponse {
  commands: string[];
}

export type ReportFormat = "json" | "markdown" | "html" | "bug_bounty";

export type ScanEvent =
  | { type: "snapshot"; scan: ScanRecord }
  | {
      type: "progress";
      timestamp: string;
      stage: string;
      percent: number;
      message: string;
      payload?: Record<string, unknown>;
    }
  | { type: "finding"; finding: Finding }
  | { type: "log"; timestamp: string; stage: string; message: string }
  | { type: "complete"; scan: ScanRecord }
  | { type: "error"; message: string };
