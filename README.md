# TRISHUL

**TRISHUL** is an authorized-scope, AI-powered security testing platform. It runs a real
attack-surface pipeline against hosts you are explicitly authorized to test, drives four
real external binaries (`httpx`, `nuclei`, `ffuf`, `nmap`), and uses AI to rank, explain
and report what it found.

TRISHUL ships in two editions that run the **same core codebase**:

| | TRISHUL LOCAL | TRISHUL PROVIDER |
|---|---|---|
| AI runs on | Your machine (Ollama, LM Studio, llama.cpp) | Your provider account (OpenAI, Anthropic, Gemini, OpenAI-compatible, custom adapter) |
| API key | Never required | You bring your own |
| Network after install | Fully offline | Needs provider reachability |
| Secrets stay | On your disk, encrypted at rest | On your disk, encrypted at rest; only the key hint leaves it |

Switching editions or providers is a runtime operation. The security engine, the tool
adapters and the pipeline never change.

> **Historical note:** this project was previously developed under the name *KAAL*. All
> product references now use the TRISHUL name.

---

## Safety and legal model

TRISHUL is for **authorized security testing only**. Scanning a host you do not own or
have written permission to test is illegal in most jurisdictions and may violate the
Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent laws elsewhere.

> "Hey kid, don't ride a horse that isn't yours"

TRISHUL enforces this in code, not just in prose:

- **Explicit confirmation.** The CLI asks you to type `YES` before a scan starts. The API
  requires `authorized: true` plus an `authorization_note` of at least 5 characters.
- **Scope enforcement.** The target is resolved once and checked against the authorized
  scope before any binary is executed; private, loopback and link-local ranges are
  refused by default.
- **Non-destructive by default.** The guide engine produces manual reproduction steps for
  you to run yourself; TRISHUL does not exploit findings on its own.
- **Policy over AI.** The AI can rank, explain and write guidance. It can never widen
  scope, bypass a gate, or run a command.

You are responsible for having written authorization before you start. TRISHUL is not a
tool for anonymous use.

---

## Features

- **Real tools, not simulations.** `httpx` (live host detection), `nuclei` (vulnerability
  scanning), `ffuf` (controlled fuzzing) and `nmap` (port scanning) are executed as real
  external binaries and their raw output is preserved as evidence.
- **Eight-stage pipeline.** `Recon → Scan → Fuzz → Detect → Verify → PoC → Guide → Report`.
- **Agent orchestration.** `MasterAgent`, `ReconAgent`, `ScannerAgent`, `FuzzerAgent`,
  `DetectionAgent`, `VerificationAgent`, `ReasoningEngine`, `PoCEngine`, `GuideEngine`,
  `ReportAgent`.
- **AI with full authority over verdicts.** Severity, confidence (0–100) and the verified
  flag come from the model when a model is reachable. The deterministic evidence score is
  still computed and stored as `baseline_confidence` so every AI decision stays auditable.
- **Graceful degradation.** When no model is reachable, the deterministic score stands and
  the AI is reported as unavailable instead of silently inventing results.
- **Interactive guidance.** The guide engine walks you through reproducing a finding
  step by step, with hints and retries, without sending destructive traffic.
- **Rich reports.** JSON, Markdown, HTML and bug-bounty-style output per scan.
- **Live dashboard.** React + TypeScript + Vite front end with live WebSocket progress,
  finding cards, logs and report downloads. The API also serves the built bundle from
  `frontend/dist`.
- **Optional enrichment.** External enrichment APIs are user-configured through a modular
  integration system (endpoint, auth, headers, params, response validation, local cache,
  rate limit). No external catalog is required at runtime.

---

## Quick start — TRISHUL LOCAL

Runs entirely on your machine. No cloud account, no API key.

```bash
cd TRISHUL
./install.sh --local          # --local offers to pull an Ollama model for you
source .venv/bin/activate
python -m backend.app.main    # API on http://127.0.0.1:8000
```

The dashboard is served by the same process at <http://127.0.0.1:8000> — it is
prebuilt and shipped, so no Node toolchain is needed. The administrator
password is printed once on first start and stored in
`data/admin-credentials.txt`.

In a second shell:

```bash
trishul example.com --mode deep
```

The default local provider is Ollama at `http://localhost:11434` with the model
`llama3.1:8b`. LM Studio (`http://localhost:1234/v1`) and llama.cpp
(`http://localhost:8080/v1`) are supported as well — see
[docs/PROVIDERS.md](docs/PROVIDERS.md).

Check what is ready at any time:

```bash
trishul --health
```

## Quick start — TRISHUL PROVIDER

Bring your own key for OpenAI, Anthropic (Claude), Google Gemini, any OpenAI-compatible
endpoint, or a custom adapter.

```bash
cd TRISHUL
./install.sh
source .venv/bin/activate
export OPENAI_API_KEY='sk-...'      # or ANTHROPIC_API_KEY / GEMINI_API_KEY
python -m backend.app.main
```

Select the provider and model at runtime — no restart, no change to the security engine:

```bash
trishul --provider-set openai --model gpt-4o-mini
trishul --provider                                  # show the active configuration
```

`--provider-set` stores the key encrypted in `data/credentials.enc`; the API and the
dashboard only ever show a hint such as `sk-...abcd`.

---

## CLI usage

```bash
trishul example.com --mode deep
```

| Flag | Meaning |
|---|---|
| `--mode quick\|deep` | Scan profile. `deep` enables the full template set and fuzzing. |
| `--threads N` | Tool thread limit (1–32). Omit to use `scan.thread_limit` from the configuration. |
| `--timeout N` | Per-tool timeout in seconds. Omit to use `scan.timeout_seconds` from the configuration. |
| `--auth-note "..."` | Authorization reference (ticket, program, scope). |
| `--yes` | Skip the interactive `YES` confirmation (a note is still required). |
| `--no-interactive` | Do not prompt for post-scan actions. |
| `--health` | Print the health report (tools, edition, AI reachability) and exit. |
| `--provider` | Show the active AI provider configuration and the provider catalog. |
| `--provider-set PROVIDER` | Switch the provider. Also accepts `--model`, `--base-url`, `--api-key`, `--edition`. |
| `--autofix` | Show, and optionally run, the commands that install missing local tools. |
| `--update` | Refresh the nuclei templates and merge local wordlists. |
| `--version` | Print the version and exit. |

Every scan invocation prints the authorization banner and asks for confirmation before any
target is contacted. The banner is drawn with plain ASCII characters only, so it renders
identically on a UTF-8 terminal, on a legacy Windows code page and in a redirected log
file; characters the host console cannot represent are degraded to `?` rather than
raising an encoding error.

---

## API and frontend development workflow

The dashboard is **prebuilt and shipped** in `frontend/dist`, so a fresh clone
serves a working dashboard at <http://127.0.0.1:8000> with no build step and no
Node toolchain. That is the built bundle the API serves.

To work on the frontend itself, run Vite next to the backend:

```bash
# Terminal 1 — backend (FastAPI, REST + WebSocket, SQLite)
source .venv/bin/activate
python -m backend.app.main --host 127.0.0.1 --port 8000

# Terminal 2 — dashboard (React + TypeScript + Vite)
cd frontend
npm install
npm run dev                                # http://localhost:5173
```

Rebuild the shipped bundle after changing the frontend:

```bash
cd frontend && npm install && npm run build
```

The dashboard reads the API base URL from `VITE_API_BASE` (default `http://localhost:8000`).
`GET /api/health` is unauthenticated; every other `/api/*` route needs
`Authorization: Bearer <access_token>` from `POST /api/auth/token`.

The backend also exposes `python -m backend.app.main --health` (JSON health report) and
`python -m backend.app.main --migrate` (apply pending migrations and exit).

The full field-level contract lives in [docs/API-CONTRACT.md](docs/API-CONTRACT.md).

---

## Editions at a glance

| | TRISHUL LOCAL | TRISHUL PROVIDER |
|---|---|---|
| AI location | Your machine | Cloud provider account |
| Default provider | Ollama (`http://localhost:11434`, `llama3.1:8b`) | OpenAI (`https://api.openai.com/v1`, `gpt-4o-mini`) |
| Key required | No | Yes, you supply it |
| Offline after setup | Yes | No, the provider must be reachable |
| Model discovery | `GET /api/tags` (Ollama), `GET /v1/models` (OpenAI-compatible) | Provider API (`/v1/models`, `/v1beta/models`) |
| Privacy | Findings never leave the host | Only prompts and evidence are sent to the provider |
| Hardware | Needs enough RAM for a local model | None beyond the scanner host |
| Best for | Air-gapped and sensitive environments | Highest-quality reasoning, no local GPU |

Full comparison and switching instructions: [docs/EDITIONS.md](docs/EDITIONS.md).

---

## Project layout

```
TRISHUL/
├── backend/
│   └── app/
│       ├── main.py              FastAPI app, routes, WebSocket, entry point
│       ├── models.py            Pydantic models and enums
│       ├── ai/                  Provider abstraction, registry and adapters
│       ├── engine/              Master agent, stage engines, report and guide
│       ├── core/                Config, storage, scope, security, secrets, events
│       └── services/            Tool adapters, tooling, reporting, health, updater
├── cli/
│   └── trishul.py               `trishul` command-line entry point
├── frontend/                    React + TypeScript + Vite dashboard
├── config/
│   ├── default.yaml             Runtime configuration
│   └── wordlists/               Fuzzing wordlists (and extra/ for local additions)
├── migrations/                  SQL migrations, applied automatically at startup
├── tests/                       pytest suite
├── docs/                        Architecture, security, guide, editions, providers, API contract
├── data/                        SQLite database, encrypted credentials, generated admin password
├── reports/                     Generated reports and raw scan artifacts
├── plugins/                     Extension notes and payload sources
├── install.sh                   Idempotent Kali/Debian installer
├── update.sh                    Controlled, non-destructive updater
├── requirements.txt             Python dependencies
└── LICENSE                      MIT
```

---

## Security highlights

- Authorization confirmation and scope gates on every scan path (CLI and API).
- Subprocess execution without `shell=True`; only allowlisted binaries can be invoked.
- SSRF protection on every outbound request, including provider and integration calls.
- Rate limiting on API routes, integrations and outbound enrichment.
- API keys and integration credentials encrypted at rest with Fernet and never returned to
  the UI — only a hint such as `sk-...abcd`. The master key lives in `data/.master_key`
  (mode `0600`) or is supplied through `TRISHUL_MASTER_KEY`.
- Sensitive-data redaction across logs, scan records and reports.
- Admin credentials written to `data/admin-credentials.txt` with mode `0600` when
  `TRISHUL_ADMIN_USER` / `TRISHUL_ADMIN_PASSWORD` are not set.
- The API binds to `127.0.0.1` by default, so the control plane is not exposed to the
  network unless you change `app.host`.
- The AI can never bypass policy, widen scope, or execute commands.

Full detail: [docs/SECURITY.md](docs/SECURITY.md).

---

## Tests

```bash
source .venv/bin/activate
pytest
```

The suite lives in `tests/` and runs with `pytest`. It covers the security
core, the scan pipeline, every tool adapter, the AI providers, the REST and
WebSocket API, the CLI, the updater and the release packaging.

Two of the suites guard the *contracts* rather than the code:

- `tests/test_frontend_contract.py` checks every request the dashboard can
  make against the live OpenAPI schema, in both directions — so a renamed
  backend route cannot break the UI silently, and the API cannot grow a
  route the UI never reaches.
- `tests/test_docs_contract.py` checks `docs/API-CONTRACT.md` against the
  same schema, so the written contract cannot drift from the code.

### Dependency audit

```bash
pip-audit --requirement requirements.txt    # Python runtime dependencies
npm audit --prefix frontend                 # frontend dependencies
```

Both are expected to report no known vulnerabilities.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `trishul: command not found` | `~/.local/bin` is not on `PATH` | `export PATH="$HOME/.local/bin:$PATH"` |
| `httpx: command not found` | Go binaries are not on `PATH` | `export PATH="$HOME/go/bin:$PATH"`, or re-run `./install.sh` |
| `nuclei` finds no templates | Templates were not downloaded | `nuclei -ut` or `trishul --update` |
| `nuclei`/`ffuf` install failed | Network or proxy blocked the Go build | Re-run `./install.sh`; the installer warns instead of aborting |
| Frontend build failed | Missing Node/npm or dependency error | Install Node 18+, then `cd frontend && npm install && npm run build` |
| `401 Unauthorized` from the API | Missing or expired bearer token | `POST /api/auth/token` and send `Authorization: Bearer <token>` |
| `422` when creating a scan | `authorization_note` shorter than 5 characters | Send a longer note |
| `400` when creating a scan | `authorized` was not `true` | Set `authorized: true` and confirm out of band |
| Cannot log in to the dashboard | Generated credentials never read | `cat data/admin-credentials.txt` (mode `0600`) |
| `Ollama` connection refused | Local model server is not running | Start Ollama, or `ollama serve` |
| AI marked unavailable | No model reachable at the configured base URL | `trishul --health`, then `trishul --provider` and `POST /api/providers/test` |
| Stored API key stops working | `data/.master_key` was regenerated or replaced | Restore the original master key, or re-enter the key with `--provider-set` |
| Scan refused before starting | Target resolves to a private or link-local address | Expected behaviour; set `security.allow_private_targets` only for an authorized internal test |
| Port 8000 already in use | Another service holds the port | `python -m backend.app.main --port 8010`, or set `app.port` in `config/default.yaml` |
| `403` from an integration | SSRF guard blocked the endpoint | Point the integration at a public HTTPS endpoint |

---

## License

MIT — see [LICENSE](LICENSE).
