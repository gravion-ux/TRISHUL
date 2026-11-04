# TRISHUL Security Model

TRISHUL is a security testing tool. Its own security posture therefore matters as much as
the findings it produces. This document describes the threats TRISHUL addresses, the
controls that address them, and the boundaries that the AI cannot cross.

> "Hey kid, don't ride a horse that isn't yours" — TRISHUL is for authorized testing only.

---

## 1. Threat model

TRISHUL runs on a workstation that the operator owns, and it points at hosts the operator
claims to be authorized to test. The realistic threats are therefore:

| # | Threat | Actor | Impact | Control |
|---|--------|-------|--------|---------|
| T1 | Scanning a host without authorization | Operator error, misuse of the tool | Legal liability, damage to third parties | Mandatory authorization gate (CLI `YES` prompt, API `authorized` + note) and scope enforcement |
| T2 | Command injection through a target, URL, wordlist or integration parameter | Remote attacker controlling scanned content | Code execution on the operator host | No `shell=True`, argv-only execution, allowlisted binaries, no shell interpolation |
| T3 | SSRF through a user-configured provider or integration | Misconfiguration or hostile target | Reaching cloud metadata or internal services, credential theft | Outbound URL validation, private and link-local range blocking, redirect re-validation, DNS re-check |
| T4 | Leaking API keys or admin credentials | Local compromise, log collection, backup copying | Account takeover, unauthorized access | Encryption at rest, `0600` file permissions, hint-only API responses, log redaction |
| T5 | Resource exhaustion from a hostile or slow target | Remote attacker | Scan stalls, host overload | Per-invocation timeouts, thread limits, rate limits, body-size caps, cache |
| T6 | AI-driven policy bypass or arbitrary execution | Prompt injection through scanned content, misconfigured model | Out-of-scope requests, unbounded actions | The AI produces text only; it has no tool access, no command execution and no policy override |
| T7 | Cross-scan data leakage | Authenticated but low-privilege operator | Reading another operator's findings | Bearer-token authentication on every `/api/*` route, per-scan ownership checks |
| T8 | Sensitive data leaking into logs or reports | Accidental | Disclosure of tokens, personal data, credentials | Central redaction filters applied before persistence and before report rendering |

Out of scope: TRISHUL is not hardened against a local root attacker, and it does not
defend the target hosts it scans. The target's own security is the operator's
responsibility.

---

## 2. Authorization and scope gates

Every scan path passes through the same gate, whether it starts from the CLI, the API or
the dashboard.

### CLI gate

```
$ trishul example.com --mode deep
Type YES to confirm you are authorised to scan this target: YES
Authorization note (ticket / program / scope reference): AC-2026-0142
```

- The confirmation must be exactly `YES`. Anything else aborts before a connection is
  opened.
- The authorization note must be at least 5 characters. `--auth-note` supplies it
  non-interactively; the note is stored on the scan record.
- `--yes` skips only the confirmation prompt. The authorization note is still required.

### API gate

```http
POST /api/scans
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "target": "example.com",
  "mode": "deep",
  "authorized": true,
  "authorization_note": "AC-2026-0142",
  "thread_limit": 8,
  "timeout_seconds": 900
}
```

- `authorized` must be `true`, otherwise the request is rejected with `400`.
- `authorization_note` must be at least 5 characters, otherwise the request is rejected
  with `422`.
- Both values are persisted on the scan record, together with the authenticated user, so
  every finding can be traced back to an authorization reference.

### Scope enforcement

After the gate, the target is normalized and resolved:

1. The target is reduced to a host and a URL form; wildcards, URLs with credentials and
   malformed input are rejected.
2. The host is resolved, and every resolved address is checked against the allowed
   scope.
3. Private, loopback, link-local, multicast and cloud-metadata ranges are refused by
   default (`security.allow_private_targets` exists for deliberate lab use).
4. The resolved address is fixed for the duration of the scan, so DNS rebinding cannot
   redirect a later stage to a different host.
5. If `security.authorized_targets` is not empty, the resolved host must be one of those
   hosts or a subdomain of one of them. This is the hard scope boundary for an
   engagement.
6. Hostnames listed in `security.blocked_hostnames` (by default `169.254.169.254`,
   `metadata.google.internal` and `metadata.goog`) are rejected even if they would
   otherwise pass the address checks.

The scan refuses to start when the target is out of scope. Scope is enforced again for
every outbound request the adapters make, not only once at the start.

---

## 3. Subprocess safety

The four external binaries are the only programs TRISHUL executes.

- **No shell.** Every tool is launched with `asyncio.create_subprocess_exec` using an
  argument vector. `shell=True` is never used, so shell metacharacters in a target, a
  URL or a wordlist entry have no effect.
- **Allowlist.** Only `httpx`, `nuclei`, `ffuf` and `nmap` may be executed. The binary
  names come from `tools` in the configuration and are resolved against the
  `allowed_binaries` list; no user-supplied command line is ever run.
- **Arguments are values, not code.** Every user-controlled value is passed as a separate
  argv element. No value is concatenated into a command string.
- **Bounded execution.** Each invocation has a timeout (`scan.timeout_seconds`) and is
  bounded by `scan.thread_limit` concurrent workers. A timed-out process is terminated,
  then killed.
- **Controlled environment.** Child processes receive a sanitized environment: the tool
  paths are set explicitly, and provider keys and admin credentials are not exported into
  the tool environment.
- **Controlled working directory.** Output is written into the scan's own artifact
  directory, so a tool cannot overwrite configuration, credentials or another scan's
  data.
- **No auto-fix from the web.** The `POST /api/update` route is authenticated, and
  `--autofix` in the CLI prints the commands and asks for confirmation before running
  them.

---

## 4. SSRF protection

Provider endpoints, integration endpoints and every outbound request made during a scan
are validated before the connection is opened:

- Only `http` and `https` URLs are accepted; schemes such as `file`, `gopher` and
  `dict` are rejected.
- The hostname is resolved and every address is checked. Loopback (`127.0.0.0/8`,
  `::1`), private (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, which
  includes the `169.254.169.254` cloud metadata address), multicast and reserved ranges
  are refused.
- IPv4-mapped IPv6 addresses are unwrapped before the check, so `::ffff:127.0.0.1`
  cannot slip past the IPv4 rules.
- Redirects are followed manually and each hop is re-validated; a redirect into a
  blocked range aborts the request.
- DNS is re-checked at connect time, which closes the DNS-rebinding window between
  validation and connection.
- Response bodies are size-capped, and only the configured JSON path is parsed.

---

## 5. Rate limiting

- API routes are rate limited per authenticated principal and per source address:
  `security.rate_limit_requests` requests per `security.rate_limit_window_seconds`
  (defaults: 120 requests per 60 seconds).
- Integration endpoints carry their own limit: `integrations.rate_limit_per_minute`
  (default 30). TRISHUL tracks the remaining budget locally and never exceeds it.
- Responses from integrations are cached locally for `integrations.cache_ttl_seconds`
  (default 3600), so repeated lookups of the same indicator do not generate repeated
  traffic. Response bodies are capped at `integrations.max_response_bytes` (default
  512000).
- Outbound scan traffic is bounded by `scan.thread_limit`,
  `scan.max_concurrent_scans`, `scan.ffuf_max_requests` and per-invocation timeouts,
  which keeps TRISHUL from flooding a target.
- The provider client applies `ai.timeout_seconds` (default 120) and backs off on a failed
  provider instead of retrying aggressively.

---

## 6. Credential storage

- AI provider API keys and integration credentials are **encrypted at rest** with Fernet
  (AES-128-CBC + HMAC-SHA256) and stored as ciphertext in `data/credentials.enc` (mode
  `0600`). Only ciphertext is ever written to disk.
- The master key lives in `data/.master_key` (mode `0600`), or is supplied by the
  operator through the environment as `TRISHUL_MASTER_KEY`. Keeping it outside the
  project tree is recommended for shared hosts:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- The API never returns a full key. `ProviderConfig` and `IntegrationConfig` expose only
  `has_api_key` and a hint built from the first five and last four characters, such as
  `sk-...abcd`.
- When no key is stored, the provider falls back to the environment variables
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` / `GOOGLE_API_KEY`,
  `TRISHUL_AI_API_KEY`, and the optional local ones `OLLAMA_API_KEY`,
  `LMSTUDIO_API_KEY`, `LLAMACPP_API_KEY`.
- Admin credentials come from `TRISHUL_ADMIN_USER` and `TRISHUL_ADMIN_PASSWORD`. If they
  are unset, a password is generated on first run and written to
  `data/admin-credentials.txt` with mode `0600`. The file is never served by the API and
  is excluded from update backups.
- Access tokens are bearer tokens issued by `POST /api/auth/token` and sent in the
  `Authorization` header. WebSocket clients may pass the token as a query parameter
  because browsers cannot set headers on a WebSocket handshake.
- `data/` holds the database, the encrypted credential store, the master key and the
  generated admin password. It is not committed and is never included in a configuration
  backup.

---

## 7. Redaction

- A central redaction filter runs over log records, scan events, error messages and
  rendered reports before they are persisted or returned.
- It masks API keys, bearer tokens, authorization headers, cookie values, private keys
  and common secret assignments (`api_key`, `token`, `password`, `secret`, `client_secret`).
- Truncated values keep only a short prefix and suffix, so a human can still match a
  value without exposing it: `sk-...abcd`.
- Raw tool output is redacted on the way into the finding's `evidence` and `raw` fields,
  so even the archived artifact copy is filtered.
- Redaction failures are logged as a warning, never silently swallowed.

---

## 8. AI boundaries

**The AI can never bypass policy and can never execute commands.** This is a structural
property, not a prompt instruction:

- The model is called through the provider abstraction, which returns text only. There is
  no path from a model reply to `exec`, to the subprocess runner, or to the tool
  registry.
- The AI has no access to credentials, to the filesystem outside the report directory,
  or to the raw environment of the backend process.
- Authorization, scope, rate limits, timeouts and the binary allowlist are enforced in
  deterministic code *before* the model is called. A model that requests an out-of-scope
  target, a new binary or a wider policy is ignored; the request is simply not offered
  to the model in the first place.
- Findings produced by the AI are still constrained by the pipeline: the AI can rank,
  explain, re-label and write guidance for evidence that a deterministic adapter
  produced. It cannot introduce a finding without underlying evidence.
- The AI's verdict is recorded with full provenance — `ai_adjusted`, the deterministic
  `baseline_confidence`, the provider and the model — so an operator can always see what
  was determined by code and what was determined by a model.
- When no model is reachable, TRISHUL does not ask a model-shaped question and does not
  fabricate a verdict: the deterministic score stands and the AI is reported unavailable.

---

## 9. Authentication, transport and audit

- Every `/api/*` route except `GET /api/health` and `POST /api/auth/token` requires a
  bearer token.
- Errors use a single shape (`{"detail": "..."}`) and never leak stack traces, file
  paths or configuration values to the client.
- Each scan record keeps the target, the authorization note, the authenticated user, the
  provider and model in use, the per-stage log and the report paths — an audit trail
  from authorization to report.
- TRISHUL binds to the configured host and port (`app.host`, `app.port`, default
  `127.0.0.1:8000`), so the control plane is not reachable from the network by default.
  The dashboard's development origin is allowed through CORS (`app.cors_origins`).
  If you expose it, put it behind a TLS-terminating reverse proxy and restrict access to
  it, because bearer tokens are carried in the `Authorization` header and the WebSocket
  query string. `TRISHUL_API_HOST` and `TRISHUL_API_PORT` override the listener without
  editing the configuration file.

---

## 10. Reporting on your own installation

If you discover a security issue in TRISHUL itself, report it privately to the
maintainers rather than in a public issue, and include the affected version, the
reproduction steps and the impact. Do not run an active scan against a TRISHUL
deployment without written authorization from its owner.
