import type {
  AutofixResponse,
  CancelScanResponse,
  ChatRequest,
  ChatResponse,
  DeletedResponse,
  EnrichmentResponse,
  Finding,
  GuideAction,
  GuideSession,
  HealthResponse,
  IntegrationConfig,
  IntegrationConfigRequest,
  IntegrationTestRequest,
  IntegrationTestResult,
  InvokeIntegrationResponse,
  MeResponse,
  ModelsResponse,
  ProviderConfig,
  ProviderConfigRequest,
  ProviderDescriptor,
  ProviderTestRequest,
  ProviderTestResult,
  ReportFormat,
  ScanRecord,
  ScanRequest,
  StartScanResponse,
  TokenResponse,
  UpdateResponse,
} from "./types";

export const API_BASE: string = import.meta.env.VITE_API_BASE || "http://localhost:8000";

const TOKEN_STORAGE_KEY = "trishul_token";
export const UNAUTHORIZED_EVENT = "trishul:unauthorized";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    /* storage unavailable — the session simply is not persisted */
  }
}

export function clearToken(): void {
  try {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

function notifyUnauthorized(): void {
  clearToken();
  window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
}

async function extractErrorMessage(response: Response): Promise<string> {
  const raw = await response.text();
  if (!raw) {
    return response.statusText || `Request failed with status ${response.status}`;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && "detail" in parsed) {
      const detail = (parsed as { detail: unknown }).detail;
      if (typeof detail === "string") {
        return detail;
      }
      if (Array.isArray(detail)) {
        const messages = detail.map((item) => {
          if (item && typeof item === "object" && "msg" in item) {
            const msg = (item as { msg: unknown }).msg;
            return typeof msg === "string" ? msg : JSON.stringify(item);
          }
          return typeof item === "string" ? item : JSON.stringify(item);
        });
        return messages.join("; ") || raw;
      }
    }
    return raw;
  } catch {
    return raw;
  }
}

interface RequestOptions extends Omit<RequestInit, "headers"> {
  headers?: HeadersInit;
  /** Attach the bearer token (default true). */
  auth?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { auth = true, headers, ...rest } = options;
  const finalHeaders = new Headers(headers);
  if (rest.body !== undefined && rest.body !== null && !finalHeaders.has("Content-Type")) {
    finalHeaders.set("Content-Type", "application/json");
  }
  const token = getToken();
  if (auth && token) {
    finalHeaders.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, { ...rest, headers: finalHeaders });

  if (response.status === 401 && auth) {
    notifyUnauthorized();
  }
  if (!response.ok) {
    throw new ApiError(response.status, await extractErrorMessage(response));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }
  return (await response.text()) as unknown as T;
}

function jsonBody(value: unknown): string {
  return JSON.stringify(value);
}

/* ---------- Authentication ---------- */

export async function login(username: string, password: string): Promise<TokenResponse> {
  const response = await request<TokenResponse>("/api/auth/token", {
    method: "POST",
    auth: false,
    body: jsonBody({ username, password }),
  });
  setToken(response.access_token);
  return response;
}

export function getMe(): Promise<MeResponse> {
  return request<MeResponse>("/api/me");
}

/* ---------- Health ---------- */

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health", { auth: false });
}

export function getAutofixCommands(): Promise<AutofixResponse> {
  return request<AutofixResponse>("/api/health/autofix");
}

export function triggerUpdate(): Promise<UpdateResponse> {
  return request<UpdateResponse>("/api/update", { method: "POST" });
}

/* ---------- Scans ---------- */

export function listScans(): Promise<ScanRecord[]> {
  return request<ScanRecord[]>("/api/scans");
}

export function getScan(scanId: string): Promise<ScanRecord> {
  return request<ScanRecord>(`/api/scans/${encodeURIComponent(scanId)}`);
}

export function startScan(payload: ScanRequest): Promise<StartScanResponse> {
  return request<StartScanResponse>("/api/scans", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function cancelScan(scanId: string): Promise<CancelScanResponse> {
  return request<CancelScanResponse>(`/api/scans/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
  });
}

export function getScanFindings(scanId: string): Promise<Finding[]> {
  return request<Finding[]>(`/api/scans/${encodeURIComponent(scanId)}/findings`);
}

export function getEnrichment(scanId: string): Promise<EnrichmentResponse> {
  return request<EnrichmentResponse>(`/api/enrichment?scan_id=${encodeURIComponent(scanId)}`);
}

/* ---------- Guides ---------- */

export function startGuide(scanId: string, findingId: string): Promise<GuideSession> {
  return request<GuideSession>(
    `/api/guides/start?scan_id=${encodeURIComponent(scanId)}`,
    {
      method: "POST",
      body: jsonBody({ finding_id: findingId }),
    },
  );
}

export function guideAction(guideId: string, action: GuideAction): Promise<GuideSession> {
  return request<GuideSession>(`/api/guides/${encodeURIComponent(guideId)}/action`, {
    method: "POST",
    body: jsonBody({ action }),
  });
}

/* ---------- Chat ---------- */

export function chat(payload: ChatRequest): Promise<ChatResponse> {
  return request<ChatResponse>("/api/chat", {
    method: "POST",
    body: jsonBody(payload),
  });
}

/* ---------- Providers ---------- */

export function getProviders(): Promise<ProviderDescriptor[]> {
  return request<ProviderDescriptor[]>("/api/providers");
}

export function getCurrentProvider(): Promise<ProviderConfig> {
  return request<ProviderConfig>("/api/providers/current");
}

export function saveProviderConfig(payload: ProviderConfigRequest): Promise<ProviderConfig> {
  return request<ProviderConfig>("/api/providers/config", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function resetProviderConfig(): Promise<ProviderConfig> {
  return request<ProviderConfig>("/api/providers/config", { method: "DELETE" });
}

export function testProvider(payload: ProviderTestRequest): Promise<ProviderTestResult> {
  return request<ProviderTestResult>("/api/providers/test", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function getModels(provider?: string, baseUrl?: string): Promise<ModelsResponse> {
  const params = new URLSearchParams();
  if (provider) {
    params.set("provider", provider);
  }
  if (baseUrl) {
    params.set("base_url", baseUrl);
  }
  const query = params.toString();
  return request<ModelsResponse>(`/api/providers/models${query ? `?${query}` : ""}`);
}

/* ---------- Integrations ---------- */

export function listIntegrations(): Promise<IntegrationConfig[]> {
  return request<IntegrationConfig[]>("/api/integrations");
}

export function createIntegration(payload: IntegrationConfigRequest): Promise<IntegrationConfig> {
  return request<IntegrationConfig>("/api/integrations", {
    method: "POST",
    body: jsonBody(payload),
  });
}

export function deleteIntegration(name: string): Promise<DeletedResponse> {
  return request<DeletedResponse>(`/api/integrations/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

export function testIntegration(
  name: string,
  payload: IntegrationTestRequest = {},
): Promise<IntegrationTestResult> {
  return request<IntegrationTestResult>(
    `/api/integrations/${encodeURIComponent(name)}/test`,
    {
      method: "POST",
      body: jsonBody(payload),
    },
  );
}

export function invokeIntegration(
  name: string,
  params: Record<string, unknown>,
): Promise<InvokeIntegrationResponse> {
  return request<InvokeIntegrationResponse>(
    `/api/integrations/${encodeURIComponent(name)}/invoke`,
    {
      method: "POST",
      body: jsonBody({ params }),
    },
  );
}

/* ---------- Reports ---------- */

export function reportUrl(scanId: string, format: ReportFormat): string {
  return `${API_BASE}/api/reports/${encodeURIComponent(scanId)}/${format}`;
}

function reportExtension(format: ReportFormat): string {
  switch (format) {
    case "json":
      return "json";
    case "markdown":
      return "md";
    case "html":
      return "html";
    case "bug_bounty":
      return "md";
  }
}

/**
 * Downloads a report with the bearer token attached and hands the browser a blob.
 * Plain `<a href>` cannot send the Authorization header, so the fetch is explicit.
 */
export async function downloadReport(scanId: string, format: ReportFormat): Promise<void> {
  const headers = new Headers();
  const token = getToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(reportUrl(scanId, format), { headers });
  if (response.status === 401) {
    notifyUnauthorized();
  }
  if (!response.ok) {
    throw new ApiError(response.status, await extractErrorMessage(response));
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = `trishul-${scanId}.${reportExtension(format)}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

/* ---------- WebSocket ---------- */

export function scanSocketUrl(scanId: string, token: string): string {
  const wsBase = API_BASE.replace(/^http/, "ws");
  return `${wsBase}/ws/scans/${encodeURIComponent(scanId)}?token=${encodeURIComponent(token)}`;
}
