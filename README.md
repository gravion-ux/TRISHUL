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
- **Scope enforcement.** Every target is normalized and resolved, and the resolved address
  is checked against the authorized scope before any binary is executed.
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
  finding cards, logs and report downloads.
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
python -m backend.app.main    # API on http://localhost:8000
```

In a second shell:

```bash
trishul example.com --mode deep
```

The default local provider is Ollama at `http://localhost:11434`. LM Studio
(`http://localhost:1234/v1`) and llama.cpp (`http://localhost:8080/v1`) are supported as
well — see [docs/PROVIDERS.md](docs/PROVIDERS.md).

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

Then select the provider at runtime (or in the dashboard):

```bash
curl -s http://localhost:8000/api/health | python -m json.tool
```

Provider and model are switchable without restarting the engine and without touching the
security engine.

---

## CLI usage

```bash
trishul example.com --mode deep
```

| Flag | Meaning |
|---|---|
| `--mode quick\|deep` | Scan profile. `deep` enables the full template set and fuzzing. |
| `--threads N` | Parallel worker limit for the tool adapters. |
| `--timeout N` | Per-scan timeout in seconds. |
| `--auth-note "..."` | Authorization reference (ticket, program, scope). |
| `--yes` | Skip the interactive `YES` confirmation (a note is still required). |
| `--autofix` | Print and optionally run the commands that install missing local tools. |

Every invocation prints the authorization banner and asks for confirmation before any
target is contacted.

---

## API and frontend development workflow

```bash
# Terminal 1 — backend (FastAPI, REST + WebSocket, SQLite)
source .venv/bin/activate
python -m backend.app.main                 # http://localhost:8000

# Terminal 2 — dashboard (React + TypeScript + Vite)
cd frontend
npm install
npm run dev                                # http://localhost:5173
```

The dashboard reads the API base URL from `VITE_API_BASE` (default `http://localhost:8000`).
`GET /api/health` is unauthenticated; every other `/api/*` route needs
`Authorization: Bearer <access_token>` from `POST /api/auth/token`.

The full field-level contract lives in [docs/API-CONTRACT.md](docs/API-CONTRACT.md).

---

## Editions at a glance

| | TRISHUL LOCAL | TRISHUL PROVIDER |
|---|---|---|
| AI location | Your machine | Cloud provider account |
| Default provider | Ollama (`http://localhost:11434`) | OpenAI (`https://api.openai.com/v1`) |
| Key required | No | Yes, you supply it |
| Offline after setup | Yes | No, the provider must be reachable |
| Model discovery | `GET /api/tags` (Ollama), `GET /v1/models` (OpenAI-compatible) | Provider API |
| Privacy | Findings never leave the host | Only prompts and evidence sent to the provider |
| Hardware | Needs enough RAM for a local model | None beyond the scanner host |
| Best for | Air-gapped and sensitive environments | Highest-quality reasoning, no local GPU |

Full comparison and switching instructions: [docs/EDITIONS.md](docs/EDITIONS.md).

---

## Project layout

```
TRISHUL/
├── backend/          FastAPI app: agents, tool adapters, storage, reporting, providers
├── cli/              `trishul` command-line launcher
├── frontend/         React + TypeScript + Vite dashboard
├── config/           Runtime defaults and wordlists
├── migrations/       Database migrations, applied automatically at startup
├── tests/            pytest suite
├── docs/             Architecture, security, user guide, editions, providers, API contract
├── data/             Runtime database and generated credentials (never committed)
├── reports/          Generated reports and raw scan artifacts
├── plugins/          Extension notes and payload sources
├── install.sh        Idempotent Kali/Debian installer
├── update.sh         Controlled, non-destructive updater
├── requirements.txt  Python dependencies
└── LICENSE           MIT
```

---

## Security highlights

- Authorization confirmation and scope gates on every scan path (CLI and API).
- Subprocess execution without `shell=True`; only allowlisted binaries can be invoked.
- SSRF protection on every outbound request, including provider and integration calls.
- Rate limiting on API routes, integrations and outbound enrichment.
- API keys and integration credentials encrypted at rest and never returned to the UI —
  only a hint such as `sk-…abcd`.
- Sensitive-data redaction across logs, scan records and reports.
- Admin credentials written to `data/admin-credentials.txt` with mode `0600` when
  `TRISHUL_ADMIN_USER` / `TRISHUL_ADMIN_PASSWORD` are not set.
- The AI can never bypass policy, widen scope, or execute commands.

Full detail: [docs/SECURITY.md](docs/SECURITY.md).

---

## Tests

```bash
source .venv/bin/activate
pytest
```

The suite lives in `tests/` and runs with `pytest`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `trishul: command not found` | `~/.local/bin` is not on `PATH` | `export PATH="$HOME/.local/bin:$PATH"` |
| `httpx: command not found` | Go binaries are not on `PATH` | `export PATH="$HOME/go/bin:$PATH"`, or re-run `./install.sh` |
| `nuclei` finds no templates | Templates were not downloaded | `nuclei -ut` |
| `nuclei`/`ffuf` install failed | Network or proxy blocked the Go build | Re-run `./install.sh`; the installer warns instead of aborting |
| Frontend build failed | Missing Node/npm or dependency error | Install Node 18+, then `cd frontend && npm install && npm run build` |
| `401 Unauthorized` from the API | Missing or expired bearer token | `POST /api/auth/token` and send `Authorization: Bearer <token>` |
| `422` when creating a scan | `authorization_note` shorter than 5 characters | Send a longer note |
| `400` when creating a scan | `authorized` was not `true` | Set `authorized: true` and confirm out of band |
| Cannot log in to the dashboard | Generated credentials never read | `cat data/admin-credentials.txt` (mode `0600`) |
| `Ollama` connection refused | Local model server is not running | Start Ollama, or `ollama serve` |
| AI marked unavailable | No model reachable at the configured base URL | Check `GET /api/health`, then `POST /api/providers/test` |
| Port 8000 already in use | Another service holds the port | Change `app.port` in `config/default.yaml` |
| `403` from an integration | SSRF guard blocked the endpoint | Point the integration at a public HTTPS endpoint |

---

## License

MIT — see [LICENSE](LICENSE).
