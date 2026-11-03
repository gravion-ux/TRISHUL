# TRISHUL — Security model

TRISHUL is a security tool. It therefore treats its own attack surface with
the same seriousness it expects from the operator.

> **Authorized use only.** TRISHUL scans targets you own or have written
> permission to test. Every scan requires an explicit authorization
> confirmation and a reference note. Running TRISHUL against a system without
> authorization is illegal in most jurisdictions and is your responsibility
> alone.

---

## 1. Threat model

TRISHUL assumes the following about its environment.

| Assumption | Consequence |
|---|---|
| The machine running TRISHUL is trusted | A local attacker with shell access already owns the box. |
| The target is hostile | Every byte returned by the target is untrusted input and is treated as such. |
| The operator may be careless | Destructive actions are impossible to trigger by accident, and the scope policy defaults to deny. |
| The AI model may be wrong, confused or manipulated | The model never decides what may be scanned or executed. |
| Secrets may leak into logs | Every log line, error message and API response passes through a redactor. |

### Out of scope

- A malicious operator who deliberately edits the source.
- Compromise of the host operating system.
- Side-channel attacks against the local model server.

---

## 2. Target authorization and scope

Authorization is enforced **in the engine**, before any tool runs. It is not
a UI checkbox and the AI cannot relax it.

### The three gates

1. **Explicit confirmation.** `POST /api/scans` requires `authorized: true`
   *and* an `authorization_note` of at least five characters. The CLI asks
   for an interactive confirmation unless `--yes` is passed, and the note is
   stored on the scan and printed in every report.
2. **Scope policy.** `core/scope.py` resolves the target and rejects it when
   it is loopback, link-local, multicast, reserved or private, unless
   `security.allow_private_targets` is explicitly enabled.
3. **Allowlist.** When `security.authorized_targets` is non-empty, only those
   hosts may be scanned.

Additionally, `security.blocked_hostnames` always denies the cloud metadata
endpoints (`169.254.169.254`, `metadata.google.internal`, `metadata.goog`)
regardless of any other setting.

### Where the check runs

Every tool adapter calls `scope.check()` before it constructs its command.
The test suite asserts that a blocked target produces **zero** subprocess
launches — not a launch that was later discarded.

---

## 3. SSRF protection

TRISHUL routinely makes HTTP requests to user-supplied URLs, which is the
classic SSRF shape. The defences:

- **Scheme allowlist.** Only `http://` and `https://` targets are accepted.
- **Address classification.** The resolved address is checked against every
  reserved range — loopback, private, link-local, multicast, reserved,
  unspecified — and rejected by default.
- **DNS rebinding.** The address that was validated is the address that is
  used. Resolution happens inside the policy check, immediately before the
  request.
- **Metadata hosts are hard-blocked** by hostname, so a DNS name that maps to
  a metadata address is still refused.
- **Redirects are not followed blindly** into a different address class.
- **Response size caps** on outbound requests limit memory abuse from a
  hostile server.

If you genuinely need to scan an internal host, set
`TRISHUL_ALLOW_PRIVATE_TARGETS=true` and use `security.authorized_targets`
to re-impose a tight allowlist. Turning it on is a deliberate act, recorded
in the environment, and the flag is documented in the README and the CLI
health output.

---

## 4. Safe subprocess execution

`backend/app/services/tool_runner.py` is the only component that may launch
a process.

| Control | Implementation |
|---|---|
| Binary allowlist | The executable must resolve to a name in `tools.allowed_binaries`. Anything else raises `ToolPolicyError`. |
| No shell | The runner passes a list and never sets `shell=True`. There is no code path that interpolates a target into a shell string. |
| No command injection | User input reaches the tools as separate argv entries or through a target file, never as a concatenated string. |
| Timeouts | Every call has a timeout; a hung scanner cannot pin a worker forever. |
| Environment control | The child environment is constructed explicitly. |
| Output capture | stdout/stderr are captured, truncated and redacted before logging. |

A regression test asserts that neither the CLI nor the runner contains
`shell=True`.

---

## 5. What TRISHUL will not do

There is no code path that:

- Executes an exploit payload against a target.
- Sends a destructive request (`DELETE`, `DROP`, `rm -rf`, format, wipe).
- Runs a command supplied by the AI or by a chat message.
- Executes a command copied from a finding's evidence.

The PoC engine produces **documentation**: reproduction steps, a read-only
request example, the expected response, impact, remediation, a screenshot
guide and a video script. A test asserts that the generated steps contain no
destructive instruction.

The guide engine walks a human through the same non-destructive steps
interactively. It never automates the request on your behalf.

---

## 6. Authentication and access control

| Control | Detail |
|---|---|
| Password storage | PBKDF2-HMAC-SHA256 with a per-install salt. The plaintext password is never stored. |
| Generated password | If no password is configured, one is generated on first run and written to `data/admin-credentials.txt` with `0600` permissions. |
| Env-configured password | `TRISHUL_ADMIN_PASSWORD` always wins, so rotating it takes effect on the next start. |
| Session tokens | HMAC-SHA256 signed, expiring bearer tokens (`auth.token_ttl_seconds`, default 24 h). |
| Token transport | `Authorization: Bearer <token>` on every `/api/*` route except `/api/health` and `/api/auth/token`. |
| WebSocket auth | `/ws/scans/{id}?token=<token>`. An unauthenticated socket is closed with code `4401`. |
| Binding | The server binds `127.0.0.1` by default, not `0.0.0.0`. |
| CORS | An explicit origin allowlist (`app.cors_origins`), never `*` combined with credentials. |

TRISHUL is a single-operator tool by design. It authenticates; it does not
implement a multi-tenant role model. Do not expose it to an untrusted
network without putting an authenticating proxy in front of it.

---

## 7. Rate limiting

Two independent limiters:

| Limiter | Scope | Default |
|---|---|---|
| `security.rate_limit_requests` | API requests per client IP | 120 / 60 s |
| `integrations.rate_limit_per_minute` | Calls to each external integration | 30 / 60 s |

The tool layer adds a third, scan-scoped cap: `scan.ffuf_max_requests`
(default 2000) bounds the total fuzzing request budget so a scan cannot turn
into an unbounded request storm against the target.

---

## 8. Secret handling

| Secret | Where it lives | How it is protected |
|---|---|---|
| AI provider API key | `data/credentials.enc` | Fernet (AES-128-CBC + HMAC) with a master key in `data/.master_key` (or `TRISHUL_MASTER_KEY`). |
| Integration API key | `data/credentials.enc` | Same store. The plaintext `integrations` table row never contains it. |
| Admin password hash | `data/credentials.enc` | PBKDF2. |
| Master key | `data/.master_key` | File permissions `0600`; excluded from packaging and from version control. |

### What the API exposes

Only a **hint** is ever returned, for example `sk-t…4f9a`:

```json
{ "has_api_key": true, "api_key_hint": "sk-t…4f9a" }
```

The key itself never appears in a response, a log line, a report or an
exception message. A test asserts the raw key is absent from the response
body.

### Legacy migration

Earlier builds stored integration keys in clear text inside the SQLite row.
On startup the integration manager moves any such value into the encrypted
store and clears the plaintext column.

---

## 9. Log redaction

`core/utils.py::redact()` scrubs secrets before anything is written to a log,
a report or an API response. It handles:

- OpenAI-style keys (`sk-…`) and Anthropic keys (`sk-ant-…`).
- Google API keys (`AIza…`).
- `Authorization: Bearer <token>` and `Authorization: <token>`, in both
  `:` and `=` forms, keeping the scheme and replacing the secret.
- `api_key=`, `secret=`, `token=`, `password=` assignments.
- Credentials embedded in a URL (`https://user:pass@host`).
- PEM private key blocks.

---

## 10. Database and filesystem

- SQLite with WAL journaling and foreign keys enabled.
- The `findings` table uses a composite primary key `(scan_id, id)` so two
  scans of the same target cannot collide.
- The report directory and the scan artifacts directory are created with
  restrictive permissions where the platform supports it.
- `.gitignore` excludes `data/*`, `reports/*`, databases, master keys,
  credential files, `.env*` files and build output.
- The release archives exclude every one of those paths; the archives are
  built from a clean tree and the contents are verified before delivery.

---

## 11. Third-party components

TRISHUL shells out to four scanners. They are external programs with their
own trust properties:

| Tool | Role | Trust note |
|---|---|---|
| `httpx` | Live host detection | Read-only HTTP requests. |
| `nmap` | Port and service detection | Sends SYN probes. |
| `nuclei` | Template-driven vulnerability scanning | Sends validation requests. |
| `ffuf` | Controlled fuzzing | Sends many requests; bounded by the request budget. |

All four are subject to the same scope policy as the rest of the system.

### No remote repository as a data source

TRISHUL's own code never clones, fetches or calls a GitHub repository. The
predecessor project's public API catalogue integration — which read a raw
file from `raw.githubusercontent.com` at runtime — was removed outright, and
a test asserts that no `raw.githubusercontent.com` reference and no `git clone`
can reappear in the Python sources.

Two related behaviours are worth stating plainly:

- `trishul --update` asks the upstream `nuclei` binary to refresh **its own**
  template set. That is the scanner updating its signature database, not
  TRISHUL calling a repository as an API. To stay fully offline, point nuclei
  at a local template directory.
- Wordlists are never downloaded. TRISHUL ships its own lists and merges
  only the files an operator places in `config/wordlists/extra/`.

---

## 12. Operator responsibilities

TRISHUL cannot make these decisions for you:

1. **Get written authorization.** Keep the ticket reference; put it in
   `--auth-note`.
2. **Scope the target correctly.** Use `security.authorized_targets` for
   engagements with several hosts.
3. **Watch the request budget.** Large wordlists mean real load on someone
   else's system.
4. **Protect the database and the key directory.** `data/` holds the
   credential store and every scan.
5. **Keep the dependencies current.** `trishul --autofix` shows the install
   commands; `update.sh` performs a controlled upgrade.
6. **Do not expose the dashboard to the internet** without a reverse proxy
   that terminates TLS and handles authentication.

---

## 13. Reporting a vulnerability in TRISHUL

If you find a security issue in TRISHUL itself, please report it privately
rather than opening a public issue. Include the version, the platform and a
reproduction. Do not test against other people's infrastructure.
