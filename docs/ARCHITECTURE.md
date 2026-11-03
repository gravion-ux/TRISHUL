# TRISHUL — Architecture

TRISHUL is an AI-assisted security assessment platform for **authorized**
targets. It drives four real scanners, turns their raw output into scored,
evidence-backed findings, and produces submission-ready reports.

This document describes how the system is put together. For the security
model see [SECURITY.md](SECURITY.md); for the REST/WebSocket contract see
[API-CONTRACT.md](API-CONTRACT.md).

---

## 1. Design goals

| Goal | How it is met |
|---|---|
| One core, two editions | The engine never imports a provider. It talks to `AIManager`, which resolves a provider at call time. |
| No fabricated results | Every finding originates from a real tool output. When a tool is missing, the scan fails loudly rather than inventing data. |
| Evidence over vibes | Confidence is computed from observed evidence by a documented formula. AI opinions are recorded as overrides on top of an auditable baseline. |
| Operator authority | Scope, authorization and rate limits are enforced in the engine, not in the UI. The AI cannot widen them. |
| Offline-capable | With a local model server, TRISHUL makes no outbound calls except to the target. |

---

## 2. Process topology

```
                    ┌──────────────────────────────────────┐
   trishul CLI ────▶│                                      │
                    │        FastAPI application            │
   Dashboard  ────▶│  (REST + WebSocket, bearer auth)      │
                    │                                      │
                    └───────────────┬──────────────────────┘
                                    │
                            TaskManager (bounded concurrency)
                                    │
                            MasterAgent (owns the pipeline)
                                    │
   ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐
   │  Re    │  Scan  │  Fuzz  │ Detect │ Verify │  PoC   │ Guide  │
   │  con   │  ner   │  zer   │        │(+Reason│        │        │
   └────────┴────────┴────────┴────────┴────────┴────────┴────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     │                             │
              ToolAdapters                   ReasoningEngine
          (httpx/nmap/nuclei/ffuf)          (dedup + AI triage)
                     │                             │
                     └──────────┬──────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
              SQLite storage        AI provider
        (scans, findings, guides)  (local or cloud)
```

---

## 3. Repository layout

```
TRISHUL/
├── backend/app/
│   ├── ai/                  AI abstraction layer
│   │   ├── base.py          AIRequest / AIResponse / AIProvider protocol
│   │   ├── registry.py      AIManager — resolves provider + key at call time
│   │   └── providers/       ollama, openai_compatible, anthropic, gemini
│   ├── core/                Framework-free building blocks
│   │   ├── config.py        Pydantic settings + YAML + env resolution
│   │   ├── events.py        In-process pub/sub for scan progress
│   │   ├── migrations.py    SQL migration runner + column reconciliation
│   │   ├── scope.py         SSRF / authorization / allowlist policy
│   │   ├── secrets.py       Fernet-encrypted credential store
│   │   ├── security.py      Password hashing, token signing, key hints
│   │   ├── storage.py       SQLite persistence
│   │   └── utils.py         Redaction, slugify, ids, time helpers
│   ├── engine/              The ten agents and the task manager
│   │   ├── base.py          AgentContext + BaseAgent
│   │   ├── master.py        MasterAgent — the pipeline driver
│   │   ├── recon.py         ReconAgent
│   │   ├── scanner.py       ScannerAgent
│   │   ├── fuzzer.py        FuzzerAgent
│   │   ├── detection.py     DetectionAgent
│   │   ├── verification.py  VerificationAgent
│   │   ├── reasoning.py     ReasoningEngine
│   │   ├── poc.py           PoCEngine
│   │   ├── guide.py         GuideEngine
│   │   ├── report.py        ReportAgent
│   │   └── tasks.py         TaskManager — concurrency, cancellation, progress
│   ├── services/
│   │   ├── tool_runner.py   Safe subprocess execution
│   │   ├── tooling.py       Tool discovery + allowlist
│   │   ├── tool_adapters.py httpx / nmap / nuclei / ffuf adapters
│   │   ├── integrations.py  External API integration manager
│   │   ├── reporting.py     Four report formats
│   │   ├── health.py        Health checks
│   │   └── updater.py       Template refresh + local wordlist merge
│   ├── templates/           Jinja2 HTML report template
│   ├── models.py            Every Pydantic schema
│   └── main.py              FastAPI app, 32 routes
├── cli/trishul.py           Command-line entry point
├── frontend/                React + TypeScript dashboard (Vite)
├── config/                  default.yaml, wordlists
├── migrations/              NNN_name.sql
├── plugins/                 Optional local extension material
├── tests/                   pytest suite
└── docs/                    This documentation set
```

---

## 4. The pipeline

`MasterAgent.run_scan()` executes eight stages in order. Each stage receives
the accumulated context and returns findings; the stages are independent so a
failure in one is recorded and the pipeline continues where it is safe to do
so.

| # | Stage | Agent | Real tool | Produces |
|---|---|---|---|---|
| 1 | `recon` | ReconAgent | `httpx` | Live hosts, technologies, titles, status codes |
| 2 | `scan` | ScannerAgent | `nuclei` | Template matches |
| 3 | `fuzz` | FuzzerAgent | `ffuf` | Discovered paths and parameters |
| 4 | `detect` | DetectionAgent | `nmap` + the above | Normalised `Finding` objects |
| 5 | `verify` | VerificationAgent + ReasoningEngine | live HTTP/TCP probes | Scored, deduplicated, adjudicated findings |
| 6 | `poc` | PoCEngine | — | Non-destructive reproduction bundle |
| 7 | `guide` | GuideEngine | — | Interactive, step-by-step manual guidance |
| 8 | `report` | ReportAgent | — | JSON, Markdown, HTML and bug-bounty reports |

### Why `ReasoningEngine` sits inside `verify`

Deduplication and AI triage are verification concerns, not a separate stage.
Keeping them in `verify` makes the stage list exactly the eight the
specification names, while still giving the reasoning engine a complete view
of every raw finding before anything is scored.

### Stage contract

```python
class BaseAgent:
    async def run(self, ctx: AgentContext, *args) -> list[Finding]: ...
```

`AgentContext` carries the scan, settings, storage, AI manager, integration
manager, scope policy, tool registry, adapters and the scan directory. An
agent never reaches for a global.

---

## 5. The AI layer

```python
class AIProvider(Protocol):
    async def complete(self, request: AIRequest) -> AIResponse: ...
    async def list_models(self) -> list[str]: ...
    async def health(self) -> AIHealth: ...
```

`AIManager` holds no provider logic of its own. It resolves the active
configuration at call time in this order:

1. Provider configuration stored in the database (set through the API or CLI).
2. `config/default.yaml`.
3. Environment overrides (`TRISHUL_AI_PROVIDER`, `TRISHUL_AI_MODEL`, …).

The API key is resolved separately, and only at the moment of use:

1. The encrypted credential store.
2. The provider's conventional environment variable (`OPENAI_API_KEY`,
   `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` / `GOOGLE_API_KEY`,
   `TRISHUL_AI_API_KEY`).

Because resolution happens per call, switching provider never touches the
engine, never restarts a scan and never invalidates a running job.

### Failure policy

`ai.fail_open` is `true` by default. If no model is reachable, the pipeline
continues with the deterministic evidence score and the scan records that the
AI was unavailable. A scan never fails because a model server is down — but
the report says so.

---

## 6. Evidence-based scoring

The `VerificationAgent` computes a deterministic baseline from what was
actually observed. The score is stored on every finding as
`baseline_confidence` and is never overwritten.

| Signal | Adjustment |
|---|---|
| Severity base (Informational/Low/Medium/High/Critical) | 10 / 25 / 40 / 55 / 70 |
| Corroborated by a second independent source | +15 |
| Asset confirmed live | +12 |
| HTTP request succeeded | +12 |
| TCP port open | +12 |
| Two or more evidence items | +8 |
| External reference present | +5 |
| nuclei match with a confirmed status | +5 |
| nmap service without a version banner | −8 |
| WAF/CDN blocked the probe | −20 |
| Endpoint returned 404 or 410 | −25 |
| ffuf hit returned 401 or 403 | −15 |
| No live, TCP or HTTP signal at all | −20 |

The result is clamped to 0–100.

### AI adjudication

When a model is available, the AI may set the final severity, confidence and
verified state. The override is stored on the finding as `ai_adjusted: true`
with the reasoning in `ai_analysis`; the deterministic baseline stays in
`baseline_confidence` so the decision remains auditable. A false-positive
verdict downgrades the finding to Informational and marks it
`likely-false-positive`.

---

## 7. Tool integration

### Execution safety

`ToolRunner` is the only way a binary is launched:

- The executable must resolve to an allowlisted binary name.
- `shell=True` is rejected; the argument vector is always a list.
- Every call has a timeout and a captured, redacted log line.
- Environment is passed explicitly, not inherited wholesale.

### Adapters

Each adapter turns one tool's output into a normalised shape and writes the
raw output next to the scan for auditability.

| Adapter | Command shape | Output parsed |
|---|---|---|
| `HttpxAdapter` | `httpx -l targets.txt -json -silent` | JSONL lines |
| `NmapAdapter` | `nmap -sV --top-ports N -oX nmap.xml` | XML (open ports only) |
| `NucleiAdapter` | `nuclei -l targets.txt -json -silent` | JSONL lines |
| `FfufAdapter` | `ffuf -w list -u URL/FUZZ -of json -o file` | ffuf's own JSON file |

The adapters also enforce the scope policy before anything is executed.

---

## 8. Persistence

SQLite, accessed through `core/storage.py`, with WAL enabled and a thread
lock around writes.

| Table | Holds |
|---|---|
| `scans` | Scan metadata, status, authorization note, artifacts |
| `findings` | One row per finding, **composite key `(scan_id, id)`** |
| `events` | Progress and log events for replay |
| `guides` | Interactive PoC sessions and their step state |
| `integrations` | External API integration definitions (never their keys) |
| `provider_config` | The active AI provider configuration |
| `cache_entries` | Integration response cache with expiry |
| `chat_messages` | Dashboard chat history |
| `schema_migrations` | Applied migration versions |

> The composite key on `findings` matters: finding identifiers are derived
> from content, so a second scan of the same target would otherwise collide
> with the first. A regression test covers this.

### Migrations

`core/migrations.py` applies every `NNN_name.sql` file in order and records
the version in `schema_migrations`. It then reconciles the live schema
against the migration files and adds any missing columns with `ALTER TABLE`.
That reconciliation step is what upgrades a database written by an older
build in place, without a manual dump-and-restore.

---

## 9. The dashboard

React 18 + TypeScript (strict) + Vite. No UI, state or icon library — only
`react` and `react-dom` at runtime.

| Component | Responsibility |
|---|---|
| `LoginPanel` | Token acquisition |
| `Sidebar` | Navigation |
| `ScanLauncher` | Target, mode, authorization confirmation |
| `ProgressPanel` | Stage, percent, elapsed time, cancellation |
| `LogStream` | Live event log over the WebSocket |
| `FindingsList` / `FindingDetail` | Severity, confidence, evidence, AI reasoning |
| `ChatPanel` | AI assistant with scan context |
| `ProviderSettings` | Provider, model, base URL, key, connection test |
| `IntegrationsPanel` | External API definitions and invocation |
| `ReportsPanel` | Report links per scan |

The API base URL comes from `import.meta.env.VITE_API_BASE` and defaults to
`http://localhost:8000`.

---

## 10. Concurrency, progress and cancellation

`TaskManager` owns the running scans.

- At most `scan.max_concurrent_scans` (default 3) run at once.
- Each scan runs as an `asyncio` task with its own cancellation flag.
- `DELETE /api/scans/{id}` cancels a running scan; a completed scan is
  reported as not cancellable rather than silently pretending.
- Progress events are published on an in-process bus and mirrored to the
  database, so a dashboard that reconnects can replay what it missed.
- `GET /ws/scans/{id}` streams a snapshot first, then live events.

---

## 11. External integrations

Integrations are the operator's own enrichment APIs — separate from the AI
provider, and entirely optional.

Each integration defines a base URL, a path, a method, an authentication
mode (`none`, `bearer`, `header`, `query`), extra headers and parameters, a
JSON path to extract, a rate limit and a cache TTL.

- The API key is stored in the encrypted credential store only. The plaintext
  database row never contains it.
- Responses are validated against a size cap before they are parsed.
- Calls are rate limited per integration and cached locally with a TTL.
- Calls are made from the server, never from the browser.

---

## 12. Deliberate non-goals

TRISHUL does **not**:

- Exploit vulnerabilities automatically or generate weaponised payloads.
- Bypass its own scope, authorization or rate-limit policy.
- Call a GitHub repository, or any other remote catalogue, as a data source.
- Ship fake integrations or simulated scan results.
- Require a cloud AI key in the LOCAL edition.
