# TRISHUL — User guide

TRISHUL assesses a target you are authorized to test, verifies what it finds,
and produces reports you can hand to a developer or submit to a bug bounty
program.

> **Before anything else:** you need written permission for the target. TRISHUL
> asks for an authorization note on every scan and stores it with the results.
> See [SECURITY.md](SECURITY.md) for the full policy.

---

## 1. Install

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/<your-account>/TRISHUL.git
cd TRISHUL
chmod +x install.sh update.sh
./install.sh
```

The installer:

1. Checks the Python version (3.11 or newer).
2. Creates `.venv` and installs the Python dependencies.
3. Installs the four scanners — from the distribution packages when they are
   available, otherwise built from source with Go.
4. Creates `data/`, `reports/` and `config/`.
5. Primes the nuclei template set.
6. Prints the next steps.

Re-running it is safe: existing steps are skipped.

### Manual install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# The four scanners
sudo apt-get install -y nmap
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

### The dashboard (frontend)

```bash
cd frontend
npm install
npm run build      # produces frontend/dist/
```

The backend serves `frontend/dist/` when it exists, so a build is all you
need. For development, `npm run dev` gives you a hot-reloading server on
port 5173; point it at the API with `VITE_API_BASE=http://localhost:8000`.

---

## 2. First run

```bash
source .venv/bin/activate
trishul --health
```

The health report shows the version, the edition, each scanner's path and
version, and whether the AI is reachable.

```
███████████  ███████ ███    ██  ███████ ██   ██ ██    ██ ███████ 

  Authorized security testing platform — Local and Provider editions

  Version    : 2.0.0
  Edition    : local
  Platform   : linux
  Ready      : yes

  Tools:
    ✓ httpx (required) — [INF] Current Version: v1.9.0
    ✓ nmap (required) — Nmap version 7.94 ( https://nmap.org )
    ✓ nuclei (required) — [INF] Nuclei Engine Version: v3.7.1
    ✓ ffuf (required) — ffuf version: 2.1.0
    ✓ python3 — Python 3.12.3
    ✓ node — v24.14.0
    ✓ npm — 11.9.0
    ✓ git — git version 2.53.0

  AI         : ollama / llama3.1:8b
  AI status  : reachable
```

`Ready : no` means a required scanner is missing. The remediation commands are
printed at the bottom of the report but are **never** executed automatically.

If a scanner is missing, `--autofix` prints the exact install command:

```bash
trishul --autofix
```

It shows every command and asks before running anything.

---

## 3. Configure the AI

### Local (no cloud key)

```bash
ollama serve
ollama pull llama3.1:8b

trishul --provider-set ollama --model llama3.1:8b
```

### Cloud

```bash
trishul --provider-set openai --model gpt-4o-mini --api-key "sk-..."
```

Or set the key in the environment and let TRISHUL pick it up:

```bash
export OPENAI_API_KEY="sk-..."
```

Keys stored through TRISHUL are encrypted at rest. See
[PROVIDERS.md](PROVIDERS.md).

---

## 4. Run a scan

```bash
trishul example.com --mode deep
```

```
  Authorized security testing platform — Local and Provider editions

  ⚠  AUTHORIZED SECURITY TESTING ONLY
  "Hey kid, don't ride a horse that isn't yours"

Target        : example.com
Mode          : deep
Authorization : TICKET-2026-0142

Type 'yes' to confirm you are authorized to test this target: yes

[recon   ] ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░  32%
[scan    ] ████████████████████████████░░░░░░░░░░░░░░░░░░  58%
...
```

### Options

| Flag | Meaning |
|---|---|
| `--mode quick` | Faster pass: top ports, fewer templates, shorter fuzz. |
| `--mode deep` | The default. Full port set, full template set. |
| `--threads N` | Tool thread limit (1–32, default 8). |
| `--timeout N` | Per-tool timeout in seconds (default 900). |
| `--auth-note TEXT` | Your ticket or scope reference. At least 5 characters. |
| `--yes` | Skip the interactive authorization prompt. |
| `--no-interactive` | Do not prompt after the scan. |

### The authorization prompt

Without `--yes`, TRISHUL asks you to confirm:

```
Type 'yes' to confirm you are authorized to test this target:
```

Answering anything else aborts the scan. This is deliberate friction.

### Where the output goes

```
reports/<scan-id>/
├── report.json      the complete machine-readable record
├── report.md        a readable summary
├── report.html      a standalone HTML document
├── bug_bounty.md    a submission-ready write-up
└── raw/             the raw tool output, for audit
```

The CLI prints the paths when the scan finishes.

---

## 5. Use the dashboard

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000> and sign in with the admin credentials.

| Panel | What it does |
|---|---|
| **Scan** | Set the target, choose the mode, confirm authorization, start. |
| **Progress** | Live stage, percentage, elapsed time, and a cancel button. |
| **Logs** | The event stream over a WebSocket. |
| **Findings** | Sort by severity or confidence; open one for its evidence and AI reasoning. |
| **Chat** | Ask the AI about the scan. It has the current findings in context. |
| **Provider** | Switch provider, change model, test the connection. |
| **Integrations** | Define your own enrichment APIs and call them. |
| **Reports** | Open or download any report for any scan. |

### Reading a finding

Every finding shows:

- **Severity** — Informational, Low, Medium, High or Critical.
- **Confidence** — 0–100, the evidence-based score.
- **Baseline** — the deterministic score before any AI override, shown
  separately so an override is visible.
- **Verified** — whether the evidence reproduced on the live asset.
- **Evidence** — the raw items each check produced.
- **AI analysis** — the model's reasoning and remediation, when a model was
  available.

A finding marked **AI adjusted** was re-scored by the model. The baseline is
kept so you can judge whether the override was sensible.

---

## 6. The interactive PoC guide

TRISHUL never sends a destructive request and never automates an exploit.
Instead, for each finding it produces a **guide**: a sequence of manual steps
you work through yourself.

1. Open the finding.
2. Start the guide.
3. Work through the steps one at a time.
4. Press **Next** when you have completed a step, **Hint** when you want a
   nudge, or **Skip**.
5. The guide records your progress and your notes.

The guide also carries a screenshot guide and a video script, so you can
record clean evidence for a report.

The PoC bundle itself contains the reproduction steps, a read-only request
example, the expected response, the impact, the remediation and the bounty
write-up.

---

## 7. Reports

Four formats, from one scan record:

| File | Use |
|---|---|
| `report.json` | Feeding another tool, or diffing two scans. |
| `report.md` | Pasting into a ticket or a chat. |
| `report.html` | Sending to a client. Self-contained, no external assets. |
| `bug_bounty.md` | Submitting to a bug bounty program. |

The bug-bounty write-up is generated from the finding's PoC bundle: title,
severity, asset, reproduction steps, request/response, impact and remediation.
It is written for a reader who has not seen the scan.

---

## 8. External integrations

Integrations are **your** APIs, used to enrich findings. They are separate
from the AI provider, and entirely optional.

In the dashboard, **Integrations → Add** takes:

| Field | Meaning |
|---|---|
| Name | A unique identifier. |
| Base URL | The server, e.g. `https://api.example.com`. |
| Path | The path, e.g. `/v1/ip-reputation`. |
| Method | `GET`, `POST`, … |
| Auth | `none`, `bearer`, `header` or `query`. |
| Auth name | The header or query parameter name. |
| API key | Stored encrypted, never returned. |
| Headers / Parameters | Extra static values. |
| Response JSON path | Where in the response the useful value is, e.g. `data.result`. |
| Rate limit | Calls per minute. |
| Cache TTL | Seconds to cache a response. |

Invoke one with:

```bash
curl -X POST http://localhost:8000/api/integrations/my-api/invoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"params": {"ip": "93.184.216.34"}}'
```

```json
{ "ok": true, "data": { ... }, "cached": false, "latency_ms": 142 }
```

---

## 9. Configuration

`config/default.yaml` holds the defaults. Every value has an environment
override.

```yaml
app:
  host: 127.0.0.1
  port: 8000

scan:
  default_mode: deep
  thread_limit: 8
  max_concurrent_scans: 3
  ffuf_max_requests: 2000

security:
  allow_private_targets: false
  authorized_targets: []
  rate_limit_requests: 120

ai:
  edition: local
  provider: ollama
  model: llama3.1:8b
```

### Environment variables

| Variable | Effect |
|---|---|
| `TRISHUL_ADMIN_USER` / `TRISHUL_ADMIN_PASSWORD` | The dashboard login. |
| `TRISHUL_API_HOST` / `TRISHUL_API_PORT` | Where the server binds. |
| `TRISHUL_ALLOW_PRIVATE_TARGETS` | Permit internal targets. Read the warning in [SECURITY.md](SECURITY.md) first. |
| `TRISHUL_EDITION` / `TRISHUL_AI_PROVIDER` / `TRISHUL_AI_MODEL` | The AI configuration. |
| `TRISHUL_MASTER_KEY` | The credential-encryption master key. |
| `TRISHUL_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

### Scanning an internal target

```yaml
security:
  allow_private_targets: true
  authorized_targets:
    - staging.internal.example
    - 10.20.0.0/16
```

Keep the allowlist tight when you enable private targets.

---

## 10. Updating

```bash
./update.sh
```

The script works in a backup-first order: it backs up the current config and
database, upgrades the Python dependencies, refreshes the nuclei templates,
re-applies any database migrations and re-verifies the install. It prints a
diff of your configuration changes.

To update just the templates and wordlists:

```bash
trishul --update
```

TRISHUL never downloads wordlists. To use a larger corpus, put it in
`config/wordlists/extra/common/` or `config/wordlists/extra/params/` and run
`trishul --update` again.

---

## 11. Troubleshooting

**`Missing required tools: nmap`** — the scanner is not installed. Run
`trishul --autofix` and follow the printed command.

**`Target is not authorized`** — the target is outside
`security.authorized_targets`, or it resolves to a private address. Either
add it to the allowlist or set `allow_private_targets`.

**`AI is not reachable`** — the model server is down or the key is missing.
`trishul --health` shows which. The scan still completes with deterministic
scores.

**`Address already in use` on port 8000** — another process holds the port.
Use `TRISHUL_API_PORT=8010`.

**The dashboard shows "Failed to fetch"** — the frontend is pointed at the
wrong API. Set `VITE_API_BASE` and rebuild, or check that the backend is
running on the expected address.

**A scan produced no findings** — that is a real result, not a bug. Check
`reports/<scan-id>/raw/` to see what each tool actually returned. If a tool
errored, its output is recorded there.

---

## 12. Getting help

- `docs/ARCHITECTURE.md` — how the system is built.
- `docs/SECURITY.md` — the security model and the authorization policy.
- `docs/EDITIONS.md` — LOCAL versus PROVIDER.
- `docs/PROVIDERS.md` — every AI backend and how to configure it.
- `docs/API-CONTRACT.md` — every REST endpoint and WebSocket event.
