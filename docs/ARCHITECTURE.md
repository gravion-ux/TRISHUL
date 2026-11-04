# TRISHUL Architecture

This document explains how a TRISHUL scan is executed, from the API request to the
written report. It complements [`API-CONTRACT.md`](API-CONTRACT.md), which is the binding
field-level contract between the backend and the dashboard.

---

## 1. Component map

```
                       +---------------------------+
                       |    TRISHUL dashboard      |
                       | React + TypeScript + Vite |
                       +-------------+-------------+
                                     |
                       REST (HTTP)   |   WebSocket (live events)
                                     v
+---------------------------------------------------------------------+
|                       FastAPI backend (async)                        |
|                                                                      |
|   +--------------------+      +-----------------------------------+   |
|   | Security middleware |----->| API layer                        |   |
|   | bearer auth        |      | scans, findings, guides,         |   |
|   | rate limiting      |      | reports, providers, integrations,|   |
|   | redaction filters  |      | chat, health                     |   |
|   +--------------------+      +-----------------+-----------------+   |
|                                                  |                    |
|                                                  v                    |
|                              +-------------------+----------------+   |
|                              |             MasterAgent            |   |
|                              | scan lifecycle + orchestration   |   |
|                              +-------------------+----------------+   |
|                                                  |                    |
|        +---------------------+--------------------+                    |
|        |                     |                    |                    |
|        v                     v                    v                    |
|  +-----------+        +--------------+     +--------------+   +--------+
|  | ReconAgent|        | ScannerAgent |     | FuzzerAgent |   | Detect |
|  |  (httpx)  |        | (nmap,nuclei)|     |   (ffuf)    |   |  /     |
|  +-----------+        +--------------+     +--------------+   | Verify |
|                                                        +------| /Reason|
|                                                               |  /PoC |
|                                                               | /Guide|
|                                                               |/Report|
|                                                               +---+---+
|                                                                   |
|                              +--------------------------------+    |
|                              | Tool adapters                 |    |
|                              | allowlisted binaries only     |    |
|                              | httpx, nuclei, ffuf, nmap     |    |
|                              +---------------+----------------+    |
|                                              |                     |
|                              +---------------v---------+          |
|                              | Provider abstraction     |<---------+
|                              | Ollama / LM Studio /     |
|                              | llama.cpp / OpenAI /      |
|                              | Anthropic / Gemini /      |
|                              | OpenAI-compatible /       |
|                              | custom adapter            |
|                              +---------------+---------+          |
|                                              |                     |
|   +----------------------+        +-----------v----------+          |
|   | Integrations         |        | SQLite storage       |          |
|   | optional enrichment  |        | data/trishul.db      |          |
|   | user-configured APIs |        | scans, findings,     |          |
|   +----------+-----------+        | guides, provider cfg |          |
|              |                    +-----------+----------+          |
|              |                                |                     |
|              v                                v                     |
|   +----------+-----------+        +-----------v---------+   +------v-----+
|   | Local cache + rate   |        | Report writer       |   | GuideEngine |
|   | limiter              |        | json / md / html /  |   | PoCEngine   |
|   +----------------------+        | bug-bounty          |   | ReportAgent |
|                                    +---------------------+   +------------+
```

Three external planes exist outside the process:

1. **The scanner binaries** (`httpx`, `nuclei`, `ffuf`, `nmap`) run as child processes.
2. **The AI provider** is reachable over HTTP from the host running TRISHUL.
3. **Optional enrichment integrations** are user-configured HTTP endpoints.

TRISHUL itself never depends on a remote catalog, a public API directory or a GitHub
repository at runtime.

---

## 2. Data flow: API request to report

```
POST /api/scans  {target, mode, authorized, authorization_note, ...}
        |
        |  auth middleware: bearer token -> principal
        |  validation: authorized == true, len(authorization_note) >= 5
        v
+---------------------+   reject    +----------------------+
| Authorization gate  |----------->| 400 / 422 response   |
| + scope resolution  |            +----------------------+
| + private-range check|
+----------+----------+
           |  authorized target
           v
+---------------------+
| MasterAgent creates |
| ScanRecord (queued) |
+----------+----------+
           |
           v
   event bus publish  --->  WebSocket /ws/scans/{scan_id}
   (progress events)          (snapshot / progress / finding / log)
           |
           v
+---------------------+   stage result   +------------------+
| Stage runner        |---------------->| Storage          |
| recon -> ... ->     |                 | SQLite (async)   |
| report               |<----------------| scans, findings  |
+---------------------+   findings/      +------------------+
           |            evidence
           v
+---------------------+
| Provider abstraction|  severity, confidence (0-100), verified,
| (AI or deterministic)| ai_analysis, PoC prose
+----------+----------+
           |
           v
+---------------------+
| Report writer       |--> reports/<scan_id>/report.json
| ReportAgent         |    reports/<scan_id>/report.md
+---------------------+    reports/<scan_id>/report.html
           |             reports/<scan_id>/report.bounty.md
           v
  ScanRecord.report_paths + artifacts (raw tool output)
```

Key properties of the flow:

- **The target is resolved once, at the gate.** Every later stage reuses the resolved
  host and the authorized scope; nothing downstream re-reads user input.
- **Raw output is preserved.** Each adapter writes the raw tool output under the scan's
  artifact directory before it is parsed, so a finding can always be traced back to the
  bytes that produced it.
- **Findings are written incrementally.** A finding is persisted as soon as it is
  produced, so a cancelled or crashed scan still returns the findings collected so far.
- **The report is derived, not authoritative.** Reports are rendered from the stored
  findings, so regenerating a report never changes the evidence.

---

## 3. Pipeline stages

The pipeline order is fixed: `Recon → Scan → Fuzz → Detect → Verify → PoC → Guide →
Report`.

| # | Stage | Agent(s) | Tooling | Produces |
|---|-------|----------|---------|----------|
| 1 | `recon` | `ReconAgent` | `httpx` | Live URL list for the authorized host |
| 2 | `scan` | `ScannerAgent` | `nmap`, `nuclei` | Port map and template matches with raw output |
| 3 | `fuzz` | `FuzzerAgent` | `ffuf` | Fuzzing hits filtered by the configured status list |
| 4 | `detect` | `DetectionAgent` | — (analysis) | Candidate findings from scanner and fuzzer output, with a deterministic evidence score |
| 5 | `verify` | `VerificationAgent`, `ReasoningEngine` | optional re-checks | Verified state, de-duplication, ranking; the AI sets severity, confidence and the verified flag |
| 6 | `poc` | `PoCEngine` | — (AI) | `PocBundle`: reproduction steps, request/response examples, impact, remediation, screenshot guide, video script, bounty report |
| 7 | `guide` | `GuideEngine` | — (AI) | `GuideStep` list for manual, non-destructive reproduction |
| 8 | `report` | `ReportAgent` | — | JSON, Markdown, HTML and bug-bounty reports, plus `report_paths` |

`ReasoningEngine` runs **inside** the `verify` stage; it is not a separate stage. The
WebSocket stage sequence is `queued`, `recon`, `scan`, `fuzz`, `detect`, `verify`, `poc`,
`guide`, `report`, then `completed` — or `failed` / `cancelled`.

### Severity and confidence

Severity levels are `Informational`, `Low`, `Medium`, `High`, `Critical`.

- The deterministic evidence score is always computed and stored as
  `baseline_confidence` (0–100).
- When a model is reachable, the AI has **full authority** over the final severity, the
  effective `confidence` and the `verified` flag. `ai_adjusted` is set to `true`.
- When no model is reachable, the deterministic score stands as the effective confidence,
  `ai_adjusted` is `false` and the health endpoint reports the AI as unavailable. TRISHUL
  never fabricates an AI verdict.

---

## 4. AI provider abstraction

All model access goes through one interface, so switching provider or model never
touches the security engine, the agents or the tool adapters.

```
                   +---------------------------+
   ScanRequest --> |   Provider abstraction    |
                   |  edition / provider kind  |
                   |  base_url / model / key   |
                   +------------+--------------+
                                |
              +-----------------+------------------+
              |                 |                  |
              v                 v                  v
        +-----------+     +-------------+    +-------------+
        |  Ollama   |     |  OpenAI /   |    |  Custom     |
        | /api/chat |     | Anthropic / |    |  adapter    |
        |           |     | Gemini /    |    | (user code) |
        |           |     | compatible  |    |             |
        +-----------+     +-------------+    +-------------+
              |                 |                  |
              +-----------------+------------------+
                                |
                                v
                     +---------------------+
                     |  Normalized reply   |
                     |  {text, provider,    |
                     |   model, fallback}   |
                     +---------------------+
```

Provider kinds (`ProviderKind`): `ollama`, `lmstudio`, `llamacpp`, `openai`, `anthropic`,
`gemini`, `openai-compatible`, `custom`.

The catalog that ships with TRISHUL:

| Kind | Edition | Default base URL | Default model | Key required | Model discovery |
|---|---|---|---|---|---|
| `ollama` | local | `http://localhost:11434` | `llama3.1:8b` | No | `GET /api/tags` |
| `lmstudio` | local | `http://localhost:1234/v1` | `local-model` | No | `GET /v1/models` |
| `llamacpp` | local | `http://localhost:8080/v1` | `local-model` | No | `GET /v1/models` |
| `openai` | provider | `https://api.openai.com/v1` | `gpt-4o-mini` | Yes | `GET /v1/models` |
| `anthropic` | provider | `https://api.anthropic.com` | `claude-3-5-sonnet-latest` | Yes | `GET /v1/models` |
| `gemini` | provider | `https://generativelanguage.googleapis.com` | `gemini-2.0-flash` | Yes | `GET /v1beta/models` |
| `openai-compatible` | provider | `http://localhost:8000/v1` | `local-model` | No | `GET /v1/models` |
| `custom` | provider | `http://localhost:8080/v1` | `custom-model` | No | `GET /v1/models` |

| Property | Behaviour |
|---|---|
| Configuration | `ProviderConfig` — edition, provider, model, base URL, timeout, encrypted key |
| Runtime switching | `POST /api/providers/config` changes provider and model without a restart |
| Key handling | Stored encrypted at rest; the API returns only `api_key_hint` such as `sk-...abcd` |
| Connectivity test | `POST /api/providers/test` returns reachability, latency and the discovered models |
| Model discovery | `GET /api/providers/models?provider=&base_url=` lists the models the endpoint exposes |
| Failure behaviour | The call returns `fallback: true`; the deterministic score stands and the AI is marked unavailable |
| Reset | `DELETE /api/providers/config` restores the defaults of the current edition |

Exact base URLs, default models and key environment variables are listed in
[`PROVIDERS.md`](PROVIDERS.md).

---

## 5. Module layout

```
TRISHUL/
├── backend/
│   └── app/
│       ├── main.py              FastAPI app, routes, WebSocket, startup, entry point
│       ├── models.py            Pydantic models and enums (mirror API-CONTRACT.md)
│       ├── ai/
│       │   ├── base.py          AIProvider interface, request/response types
│       │   ├── registry.py      AIManager, provider catalog, key resolution
│       │   └── providers/       Ollama, Anthropic, Gemini, OpenAI-compatible adapters
│       ├── engine/
│       │   ├── master.py        MasterAgent: lifecycle, stage orchestration
│       │   ├── recon.py         ReconAgent
│       │   ├── scanner.py       ScannerAgent
│       │   ├── fuzzer.py        FuzzerAgent
│       │   ├── detection.py     DetectionAgent
│       │   ├── verification.py  VerificationAgent
│       │   ├── reasoning.py     ReasoningEngine
│       │   ├── poc.py           PoCEngine
│       │   ├── guide.py         GuideEngine
│       │   ├── report.py        ReportAgent
│       │   └── tasks.py         Cancellation and task bookkeeping
│       ├── core/
│       │   ├── config.py        Settings loaded from config/default.yaml
│       │   ├── storage.py       SQLite persistence (scans, findings, guides)
│       │   ├── scope.py         Target normalization and scope policy
│       │   ├── security.py      Rate limiting, redaction helpers, security checks
│       │   ├── secrets.py       Fernet-encrypted credential store
│       │   ├── migrations.py    Migration runner (python -m backend.app.core.migrations)
│       │   ├── events.py        In-process event bus for live updates
│       │   └── utils.py         Stable IDs, timestamps, redaction helpers
│       └── services/
│           ├── tool_adapters.py httpx, nuclei, ffuf and nmap adapters
│           ├── tool_runner.py   Safe subprocess execution (no shell=True)
│           ├── tooling.py       Tool registry, detection, autofix commands
│           ├── integrations.py  User-configured enrichment integrations
│           ├── reporting.py     JSON / Markdown / HTML / bug-bounty reports
│           ├── health.py        Health, readiness and tool status
│           └── updater.py       Nuclei template refresh and local wordlist merge
├── cli/
│   └── trishul.py               `trishul` command-line entry point
├── frontend/                    React + TypeScript + Vite dashboard
├── config/
│   ├── default.yaml             Runtime configuration
│   └── wordlists/               Fuzzing wordlists (extra/ for operator-supplied lists)
├── migrations/                  SQL migrations, applied automatically at startup
├── tests/                       pytest suite
├── docs/                        This documentation set + API-CONTRACT.md
├── data/                        SQLite database and encrypted credentials
├── reports/                     Generated reports and raw artifacts
└── plugins/                     Extension notes and payload sources
```

### Configuration sections

`config/default.yaml` keeps the established `app`, `scan` and `tools` sections and adds
`ai`, `auth`, `integrations` and `security`. Every value can be overridden with an
environment variable.

| Section | Purpose | Keys |
|---|---|---|
| `app` | Process identity, paths and listener | `name`, `version`, `db_path`, `reports_dir`, `plugins_dir`, `log_level`, `host`, `port`, `cors_origins` |
| `scan` | Scan defaults and limits | `default_mode`, `timeout_seconds`, `thread_limit`, `max_concurrent_scans`, `ffuf_max_requests`, `ffuf_status_filter`, `wordlist`, `param_wordlist` |
| `tools` | Binary names, wordlists and the executable allowlist | `httpx`, `nuclei`, `ffuf`, `nmap`, `ffuf_wordlist`, `param_wordlist`, `allowed_binaries` |
| `ai` | Edition, provider, model, base URL and request shaping | `edition`, `provider`, `model`, `base_url`, `timeout_seconds`, `max_tokens`, `temperature`, `fail_open` |
| `auth` | Admin identity and token lifetime | `enabled`, `username`, `password`, `token_ttl_seconds` |
| `security` | Policy gates | `allow_private_targets`, `authorized_targets`, `rate_limit_requests`, `rate_limit_window_seconds`, `blocked_hostnames` |
| `integrations` | Defaults for the optional enrichment system | `cache_ttl_seconds`, `rate_limit_per_minute`, `timeout_seconds`, `max_response_bytes` |

Environment overrides (highest precedence): `TRISHUL_CONFIG` (alternative YAML path),
`TRISHUL_EDITION`, `TRISHUL_AI_PROVIDER`, `TRISHUL_AI_MODEL`, `TRISHUL_AI_BASE_URL`,
`TRISHUL_AI_TIMEOUT`, `TRISHUL_ADMIN_USER`, `TRISHUL_ADMIN_PASSWORD`,
`TRISHUL_API_HOST`, `TRISHUL_API_PORT`, `TRISHUL_ALLOW_PRIVATE_TARGETS`,
`TRISHUL_LOG_LEVEL`, and `TRISHUL_MASTER_KEY` for the credential-encryption master key.

The backend binds to `127.0.0.1:8000` by default. Expose it deliberately — behind a
TLS-terminating reverse proxy — because bearer tokens travel in the `Authorization`
header and in the WebSocket query string.

---

## 6. Concurrency, progress and cancellation

### Concurrency

- The backend is fully asynchronous: FastAPI routes and the agent pipeline are `async`,
  and database access is awaited rather than blocking the event loop.
- Independent work inside a stage runs concurrently. `scan` runs `nmap` and `nuclei` in
  parallel with `asyncio.gather`; the pipeline itself advances stage by stage so the
  progress percentage stays monotonic.
- Tool adapters cap concurrency with `scan.thread_limit` (1–32), the number of scans
  running at once is bounded by `scan.max_concurrent_scans`, and each invocation carries
  a timeout (`scan.timeout_seconds`, 30–7200) so a hung binary cannot pin the scan
  forever.
- Fuzzing is bounded by `scan.ffuf_max_requests` (default 2000) and filtered by
  `scan.ffuf_status_filter`, so a scan cannot turn into an unbounded request storm
  against the target.
- Subprocesses are created with `asyncio.create_subprocess_exec` — argument vectors, no
  shell — and are terminated on timeout or cancellation.

### Progress

```
  agent.emit(scan, stage, percent, message)
        |
        +--> scan.progress = ScanProgress(stage, percent, message)
        +--> scan.logs.append(event)
        +--> storage.save_scan(scan)          (durable)
        +--> event_bus.publish(scan_id, event) (live)
                                       |
                       +---------------+----------------+
                       |                                |
                WebSocket /ws/...              CLI stdout (progress bar)
                (progress / finding / log)       (same event stream)
```

Every stage boundary and every significant sub-step emits an event, so the dashboard and
the CLI show the same progression: `queued → recon → scan → fuzz → detect → verify → poc
→ guide → report → completed`. The WebSocket stream opens with a `snapshot` event so a
client that connects late still sees the current state, and ends with `complete` or
`error`.

### Cancellation

- `DELETE /api/scans/{scan_id}` sets a cancellation flag and returns
  `{scan_id, status, cancelled}`.
- The stage runner checks the flag between stages and between tool invocations, and
  passes it down to running subprocesses, which are terminated and then killed after a
  grace period.
- A cancelled scan keeps its status `cancelled`, keeps the findings collected so far and
  does not write a final report.
- A failed scan keeps `status: failed` and records the error message on the record.

### Storage and reporting

- SQLite is the system of record. It is created on first run and migrations from
  `migrations/` are applied automatically at startup.
- Findings, evidence and guide sessions are stored with the scan, so a dashboard reload
  or a CLI re-run always sees the same history.
- Reports are rendered from the stored findings and written under
  `reports/<scan_id>/`, with the raw tool artifacts alongside them.
