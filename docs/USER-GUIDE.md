# TRISHUL User Guide

This guide takes you from a fresh machine to a finished, reported scan. It assumes Kali
Linux (Debian and Ubuntu work the same way; the backend and CLI also run on other POSIX
hosts, but the installer is Linux-first).

> **Authorized testing only.** TRISHUL refuses to start a scan without an explicit
> authorization confirmation and a note. Use it on hosts you own or have written
> permission to test.

---

## 1. Install

```bash
cd TRISHUL
./install.sh
```

The installer is idempotent — run it again any time to repair a broken installation. It:

1. installs the system packages (`python3`, `python3-venv`, `python3-pip`, `git`, `curl`,
   `wget`, `nmap`, `golang`, `nodejs`, `npm`) and `ffuf` when apt has it;
2. builds `httpx`, `nuclei` and `ffuf` from source with Go;
3. creates `.venv`, upgrades pip and installs `requirements.txt`;
4. installs the `~/.local/bin/trishul` launcher;
5. creates `data/`, `reports/` and `plugins/`;
6. downloads the nuclei templates;
7. installs and builds the dashboard;
8. runs a health check and prints a ready/missing summary.

### Options

```bash
./install.sh --help               # full help
./install.sh --local              # LOCAL edition: offers to pull an Ollama model
./install.sh --ollama-model qwen2.5:7b-instruct   # pull a specific model instead
./install.sh --no-frontend        # skip the dashboard build (API/CLI only hosts)
```

Network problems never abort the installer. If a step fails, the script warns and the
final summary tells you exactly what is missing.

### Put the launcher on your PATH

```bash
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
```

Add that line to `~/.bashrc` to make it permanent — the installer already adds the Go
path for you.

### Check the installation

```bash
trishul --health
```

You should see the four scanning tools marked as present, the edition, and the AI
provider with its reachability. Anything missing is listed with the command that fixes
it.

---

## 2. Choose your edition

### LOCAL (AI on your machine, no key)

```bash
ollama serve
ollama pull llama3.1:8b
trishul --provider-set ollama --model llama3.1:8b
```

### PROVIDER (AI in the cloud, your key)

```bash
export OPENAI_API_KEY='sk-...'
trishul --provider-set openai --model gpt-4o-mini
```

Other providers work the same way — see [PROVIDERS.md](PROVIDERS.md).

---

## 3. Start the backend

```bash
source .venv/bin/activate
python -m backend.app.main
```

The API listens on `http://127.0.0.1:8000` and prints where the generated administrator
credentials were written:

```
[!] Generated administrator credentials written to .../data/admin-credentials.txt
```

On the first run, read them once:

```bash
cat data/admin-credentials.txt
```

Set `TRISHUL_ADMIN_USER` and `TRISHUL_ADMIN_PASSWORD` before starting to use your own
credentials instead.

Useful server flags:

```bash
python -m backend.app.main --port 8010       # different port
python -m backend.app.main --host 0.0.0.0    # expose on the network (read SECURITY.md first)
python -m backend.app.main --health          # JSON health report and exit
python -m backend.app.main --migrate         # apply pending migrations and exit
```

---

## 4. Run your first scan

### From the CLI

```bash
trishul example.com --mode deep
```

```
######## ########  ####  ######  ##     ## ##     ## ##
   ##    ##     ##  ##  ##    ## ##     ## ##     ## ##
   ##    ##     ##  ##  ##       ##     ## ##     ## ##
   ##    ########   ##   ######  ######### ##     ## ##
   ##    ##   ##    ##        ## ##     ## ##     ## ##
   ##    ##    ##   ##  ##    ## ##     ## ##     ## ##
   ##    ##     ## ####  ######  ##     ##  #######  ########

  Authorized security testing platform - Local and Provider editions

  [!]  AUTHORIZED SECURITY TESTING ONLY
  "Hey kid, don't ride a horse that isn't yours"

  AI provider : ollama (llama3.1:8b) @ http://localhost:11434
  Edition     : local

Type YES to confirm you are authorised to scan this target: YES
Authorization note (ticket / program / scope reference): AC-2026-0142

[############################--] 100% report    Reports generated
```

The banner is drawn with plain ASCII characters only, so it renders
identically on a UTF-8 terminal, on a legacy Windows code page (`cp437`,
`cp1252`) and in a redirected log file. Characters that the host console
cannot represent -- for example text produced by an AI model -- are
degraded to `?` instead of raising an encoding error.

The scan runs `Recon → Scan → Fuzz → Detect → Verify → PoC → Guide → Report`. The
progress bar shows the current stage.

Useful flags:

| Flag | Effect |
|---|---|
| `--mode quick` | Faster profile with less fuzzing |
| `--threads 16` | More parallel tool workers (1–32). Omit to use `scan.thread_limit` from the configuration. |
| `--timeout 1800` | Longer per-tool timeout. Omit to use `scan.timeout_seconds` from the configuration. |
| `--auth-note "AC-2026-0142"` | Supply the authorization note non-interactively |
| `--yes` | Skip the `YES` prompt (the note is still required) |
| `--no-interactive` | Do not ask what to do after the scan |

### From the API

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://127.0.0.1:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "target": "example.com",
        "mode": "deep",
        "authorized": true,
        "authorization_note": "AC-2026-0142",
        "thread_limit": 8,
        "timeout_seconds": 900
      }'
```

Both `authorized: true` and an `authorization_note` of at least 5 characters are
required; otherwise the request is rejected with `400` or `422`.

`thread_limit` and `timeout_seconds` are optional. When you leave them out, TRISHUL
uses `scan.thread_limit` and `scan.timeout_seconds` from the configuration. When you
do supply them, those are the exact limits the scan runs with — the resolved values are
stored on the scan record.

---

## 5. Read the findings

### In the terminal

The CLI prints every finding after the scan:

```
[High] Exposed admin panel at /admin
  Asset      : https://example.com/admin
  Confidence : 87 (evidence baseline 72) | verified: true
  AI         : adjudicated this finding
  Administrative interface exposed on the public interface.
  Request    : GET /admin HTTP/1.1
  Impact     : Attackers can attempt administrative login attempts.
  Fix        : Restrict the interface to an allowlist or VPN.
```

Read the two confidence numbers carefully:

- **`baseline_confidence`** is the deterministic evidence score computed from the raw
  tool output.
- **`confidence`** is the effective score. When an AI adjudicated the finding, it is the
  AI's score and `ai_adjusted` is `true`. When no model was reachable, the deterministic
  score stands.

`verified: true` means the finding was confirmed during the verify stage.

### Through the API

```bash
curl -s http://127.0.0.1:8000/api/scans -H "Authorization: Bearer $TOKEN"          # all scans
curl -s http://127.0.0.1:8000/api/scans/<scan_id> -H "Authorization: Bearer $TOKEN" # one scan
curl -s http://127.0.0.1:8000/api/scans/<scan_id>/findings -H "Authorization: Bearer $TOKEN"
```

A finding carries its evidence, its references, the optional PoC bundle, the guide steps
and the AI analysis.

### In the dashboard

Open the dashboard (see step 8) and pick a scan. The findings table shows severity,
confidence, verified state and the source tool; selecting a finding opens the evidence
and the AI analysis.

---

## 6. Use the guide engine

The guide engine turns a finding into a short, **non-destructive** manual reproduction
walkthrough. TRISHUL never exploits a finding for you — you run the steps.

### From the CLI

After a scan you are asked what to do next:

```
What would you like to do?
1. Guide me step-by-step (manual PoC)
2. Show report paths only
3. Skip
```

Choose `1`, then select the finding to work through:

```
Step 2/5
  Open the URL in a browser and observe the response headers.

Action [next/done/hint/retry]: hint
Hint: Compare the headers with a request to an unauthenticated path.
```

- `next` — advance to the next step
- `done` — mark the current step as finished
- `hint` — show a hint for the current step
- `retry` — repeat the current step

### Through the API

```bash
# Start a guide for one finding
curl -s -X POST "http://127.0.0.1:8000/api/guides/start?scan_id=<scan_id>" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"finding_id": "<finding_id>"}'

# Advance it
curl -s -X POST http://127.0.0.1:8000/api/guides/<guide_id>/action \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action": "next"}'
```

The action is one of `next`, `done`, `hint`, `retry`. The session stores its history, so
you can leave and come back.

---

## 7. Generate reports

Reports are written at the end of every scan under `reports/<scan_id>/` in four formats:
JSON, Markdown, HTML and a bug-bounty-style document.

```bash
# From the CLI, the paths are printed at the end of the scan
trishul example.com --mode deep

# From the API
curl -s -o report.json      http://127.0.0.1:8000/api/reports/<scan_id>/json      -H "Authorization: Bearer $TOKEN"
curl -s -o report.md        http://127.0.0.1:8000/api/reports/<scan_id>/markdown  -H "Authorization: Bearer $TOKEN"
curl -s -o report.html      http://127.0.0.1:8000/api/reports/<scan_id>/html      -H "Authorization: Bearer $TOKEN"
curl -s -o bounty.md        http://127.0.0.1:8000/api/reports/<scan_id>/bug_bounty -H "Authorization: Bearer $TOKEN"
```

Each report contains the findings with their severity, confidence and evidence, the
reproduction steps, the impact and the remediation, and the raw artifact references.

The raw tool output sits next to the reports in the same scan directory, so every
finding can be traced back to the bytes that produced it.

---

## 8. Run the dashboard

### Development

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The dashboard talks to `http://localhost:8000` by default; set `VITE_API_BASE` to point
it elsewhere. Log in with the credentials from `data/admin-credentials.txt`.

### Production

```bash
cd frontend
npm install
npm run build      # writes frontend/dist
```

The backend serves the built bundle automatically on `http://127.0.0.1:8000`, so no
second process is needed.

In the dashboard you can:

- start a scan and watch it progress live over the WebSocket;
- browse findings, evidence and AI analysis;
- run the guide engine step by step;
- download the four report formats;
- switch the AI provider and model, and test the connection;
- configure optional enrichment integrations.

---

## 9. Optional: enrichment integrations

External enrichment is **optional** and entirely user-configured. Nothing is fetched
unless you create an integration yourself.

```bash
curl -s -X POST http://127.0.0.1:8000/api/integrations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "my-lookup",
        "base_url": "https://api.example.com",
        "path": "/v1/lookup",
        "method": "GET",
        "auth_type": "bearer",
        "auth_name": "Authorization",
        "api_key": "...",
        "params": {"q": "{{asset}}"},
        "response_json_path": "data",
        "rate_limit_per_minute": 30,
        "cache_ttl_seconds": 3600
      }'
```

Test it with `POST /api/integrations/<name>/test`, invoke it with
`POST /api/integrations/<name>/invoke`, and remove it with
`DELETE /api/integrations/<name>`. Integration keys are encrypted at rest, and the
endpoint is subject to the same SSRF protection as everything else.

---

## 10. Keep TRISHUL up to date

```bash
./update.sh
```

The updater backs up `config/` first (never `data/`, so no secret is copied), upgrades
the Python dependencies, refreshes the nuclei templates, rebuilds the dashboard, runs the
migrations and finishes with a health check. If any step fails it stops and prints the
rollback command.

```bash
./update.sh --tools          # also rebuild httpx, nuclei and ffuf (off by default)
./update.sh --no-frontend    # skip the dashboard rebuild
```

The nuclei templates and local wordlists can also be refreshed from the CLI:

```bash
trishul --update
```

---

## 11. When something goes wrong

| Symptom | What to do |
|---|---|
| `trishul: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| A tool is reported missing | `trishul --health` prints the exact fix command for each tool |
| The AI is unreachable | `trishul --provider` to check the base URL and model, then `trishul --health` |
| The scan is rejected before starting | The target is out of scope or resolves to a private address — expected behaviour |
| The dashboard cannot log in | Read `data/admin-credentials.txt`, or set `TRISHUL_ADMIN_USER` / `TRISHUL_ADMIN_PASSWORD` |
| Reports are empty | The scan produced no findings; check the per-stage log on the scan record |

More detail: [SECURITY.md](SECURITY.md) for the policy model, [EDITIONS.md](EDITIONS.md)
for choosing an edition, [PROVIDERS.md](PROVIDERS.md) for AI configuration and
[ARCHITECTURE.md](ARCHITECTURE.md) for how the pipeline works.
