# TRISHUL AI Providers

TRISHUL talks to exactly one AI provider at a time, but it can talk to any of them at
runtime. Switching provider or model never touches the security engine, the tool
adapters or the pipeline — only the provider configuration changes.

---

## Quick reference

| Kind | Edition | Default base URL | Default model | Key environment variable | Discovery endpoint |
|---|---|---|---|---|---|
| `ollama` | local | `http://localhost:11434` | `llama3.1:8b` | `OLLAMA_API_KEY` (optional) | `GET /api/tags` |
| `lmstudio` | local | `http://localhost:1234/v1` | `local-model` | `LMSTUDIO_API_KEY` (optional) | `GET /v1/models` |
| `llamacpp` | local | `http://localhost:8080/v1` | `local-model` | `LLAMACPP_API_KEY` (optional) | `GET /v1/models` |
| `openai` | provider | `https://api.openai.com/v1` | `gpt-4o-mini` | `OPENAI_API_KEY` | `GET /v1/models` |
| `anthropic` | provider | `https://api.anthropic.com` | `claude-3-5-sonnet-latest` | `ANTHROPIC_API_KEY` | `GET /v1/models` |
| `gemini` | provider | `https://generativelanguage.googleapis.com` | `gemini-2.0-flash` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `GET /v1beta/models` |
| `openai-compatible` | provider | `http://localhost:8000/v1` | `local-model` | `OPENAI_API_KEY` or `TRISHUL_AI_API_KEY` | `GET /v1/models` |
| `custom` | provider | `http://localhost:8080/v1` | `custom-model` | `TRISHUL_AI_API_KEY` | `GET /v1/models` |

The local providers never require a key. The cloud providers always do.

---

## How the active provider is resolved

TRISHUL resolves the active configuration in this order:

1. **A saved provider configuration** (stored in the database, changed through the CLI,
   the dashboard or `POST /api/providers/config`). This always wins.
2. **Environment overrides**: `TRISHUL_EDITION`, `TRISHUL_AI_PROVIDER`,
   `TRISHUL_AI_MODEL`, `TRISHUL_AI_BASE_URL`, `TRISHUL_AI_TIMEOUT`. These are applied
   on top of the YAML file.
3. **The YAML defaults** in `config/default.yaml` — or in `config/default.local.yaml` /
   `config/default.provider.yaml` when `TRISHUL_CONFIG` points at them.
4. **The provider catalogue default** — the endpoint and model documented for the
   selected provider. This is the lowest layer and only applies when nothing above it
   supplies a value.

A saved configuration therefore outranks an environment variable: pinning
`TRISHUL_AI_MODEL` does not override a model that was already saved through the
dashboard. Clear the saved configuration (`DELETE /api/providers/config`) to fall back
to the environment and the file again.

API keys are never part of the configuration file. They are resolved from the encrypted
credential store first, and from the environment variables in the table above second.

### Switching the provider moves the endpoint and the model

Changing the provider changes where TRISHUL connects and what it asks for. When
`TRISHUL_AI_PROVIDER` selects a different provider, TRISHUL adopts that provider's
documented endpoint and model instead of keeping the previous ones:

```bash
TRISHUL_AI_PROVIDER=anthropic trishul --health
# -> https://api.anthropic.com, claude-3-5-sonnet-latest
```

`TRISHUL_AI_BASE_URL` and `TRISHUL_AI_MODEL` are never overwritten — if you pin them
yourself, they stay exactly as you set them. This is what makes a self-hosted
OpenAI-compatible endpoint work:

```bash
TRISHUL_AI_PROVIDER=openai-compatible \
TRISHUL_AI_BASE_URL=http://vllm.internal:8000/v1 \
TRISHUL_AI_MODEL=qwen2.5-7b-instruct \
trishul --health
```

An explicit `TRISHUL_AI_PROVIDER` always wins over the edition default, so the
PROVIDER edition never silently rewrites a provider you chose yourself. The edition
only promotes a *local* provider to a hosted one when you have not chosen one.

---

## Setting the provider

### From the CLI

```bash
trishul --provider                                   # show the active configuration + catalog
trishul --provider-set ollama --model llama3.1:8b
trishul --provider-set openai --model gpt-4o-mini --api-key 'sk-...'
trishul --provider-set anthropic --model claude-3-5-sonnet-latest
trishul --provider-set openai-compatible --base-url http://localhost:1234/v1 --model qwen2.5-7b-instruct
```

`--provider-set` accepts `--provider`, `--model`, `--base-url`, `--api-key` and
`--edition`. A key passed with `--api-key` is encrypted immediately and stored in
`data/credentials.enc`.

### From the API

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"'"$TRISHUL_PASSWORD"'"}' | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://127.0.0.1:8000/api/providers/config \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"provider":"openai","model":"gpt-4o-mini","api_key":"sk-..."}'
```

Omitting `api_key` keeps the stored key. The response contains only `has_api_key` and a
hint such as `sk-...abcd`.

### Related endpoints

| Purpose | Request |
|---|---|
| List the catalog | `GET /api/providers` |
| Show the active provider | `GET /api/providers/current` |
| Test a configuration | `POST /api/providers/test` with `{provider, model, base_url, api_key}` (all optional) |
| Discover models | `GET /api/providers/models?provider=&base_url=` |
| Reset to the edition default | `DELETE /api/providers/config` |

---

## Local providers

### Ollama (default)

```bash
ollama serve
ollama pull llama3.1:8b
trishul --provider-set ollama --model llama3.1:8b
```

- Base URL `http://localhost:11434`; completions are posted to `/api/chat`.
- Model discovery reads `GET /api/tags`, which returns the models you have pulled, for
  example `llama3.1:8b` and `qwen2.5:7b-instruct`.
- The installer can pull the model for you: `./install.sh --local` (add
  `--ollama-model <name>` to choose a different one).
- If Ollama is installed but not running, `trishul --health` reports it as unreachable
  and the scan still completes with deterministic results.

### LM Studio

1. Open LM Studio, download a model and load it.
2. Enable the local server (default port 1234).
3. Point TRISHUL at it:

```bash
trishul --provider-set lmstudio --base-url http://localhost:1234/v1 --model local-model
```

- Base URL `http://localhost:1234/v1`; completions are posted to
  `/v1/chat/completions`.
- Model discovery reads `GET /v1/models`, which lists the model LM Studio has loaded.
  Use the identifier it reports if `local-model` does not match.

### llama.cpp server

```bash
llama-server -m model.gguf --port 8080
trishul --provider-set llamacpp --base-url http://localhost:8080/v1 --model local-model
```

- Base URL `http://localhost:8080/v1`; completions are posted to `/v1/chat/completions`.
- Model discovery reads `GET /v1/models`.

---

## Cloud providers

### OpenAI

```bash
export OPENAI_API_KEY='sk-...'
trishul --provider-set openai --model gpt-4o-mini
```

- Base URL `https://api.openai.com/v1`; completions are posted to `/v1/chat/completions`.
- Model discovery reads `GET /v1/models`.
- Any model in your account that speaks chat completions works — set it with `--model`.

### Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY='sk-ant-...'
trishul --provider-set anthropic --model claude-3-5-sonnet-latest
```

- Base URL `https://api.anthropic.com` (no `/v1` suffix — TRISHUL appends the path);
  completions are posted to `/v1/messages`.
- Model discovery reads `GET /v1/models`.

### Google Gemini

```bash
export GEMINI_API_KEY='...'
trishul --provider-set gemini --model gemini-2.0-flash
```

- Base URL `https://generativelanguage.googleapis.com`; completions are posted to
  `/v1beta/models/<model>:generateContent`.
- Model discovery reads `GET /v1beta/models`.
- `GOOGLE_API_KEY` is accepted as an alternative to `GEMINI_API_KEY`.

---

## OpenAI-compatible endpoints

Any server that speaks the OpenAI chat-completions dialect works. Select the
`openai-compatible` provider and set the base URL to the server's `/v1` root.

```bash
trishul --provider-set openai-compatible --base-url http://HOST:PORT/v1 --model MODEL_ID
```

| Server | Base URL | Model id | Notes |
|---|---|---|---|
| LM Studio | `http://localhost:1234/v1` | as reported by `/v1/models` | Start the local server and load a model |
| llama.cpp | `http://localhost:8080/v1` | as reported by `/v1/models` | `llama-server -m model.gguf --port 8080` |
| vLLM | `http://localhost:8000/v1` | the served model name | Start with `vllm serve <model>` |
| Ollama (OpenAI-compatible) | `http://localhost:11434/v1` | e.g. `llama3.1:8b` | Same daemon as the native provider |
| LiteLLM | `http://localhost:4000/v1` | the routed model name | Add `OPENAI_API_KEY` only if your proxy requires it |
| OpenRouter | `https://openrouter.ai/api/v1` | e.g. `anthropic/claude-3.5-sonnet` | Requires an OpenRouter key |

Notes:

- The base URL must include the `/v1` root: TRISHUL appends `/chat/completions` and
  `/models` to it.
- Keys are optional for local servers. If the server does require one, export
  `TRISHUL_AI_API_KEY` (or `OPENAI_API_KEY`) or store it with `--api-key`.
- The `custom` provider kind uses the same OpenAI-compatible transport with a base URL
  and model of your choosing. Use it when you want the configuration to be clearly
  separate from the named OpenAI-compatible preset.

---

## Key storage and safety

- Keys entered through the CLI, the dashboard or the API are encrypted with Fernet and
  written to `data/credentials.enc` (mode `0600`). The master key is in
  `data/.master_key` (mode `0600`) or in `TRISHUL_MASTER_KEY`.
- The API never returns a full key — only `has_api_key` and a hint built from the first
  five and last four characters.
- If you lose `data/.master_key`, the stored keys cannot be decrypted. Re-enter the key
  with `--provider-set` or through the dashboard.
- The `update.sh` backup deliberately excludes `data/`, so credentials are never copied
  into a backup archive.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Ollama is not reachable at http://localhost:11434` | The daemon is not running | `ollama serve` |
| `Ollama returned HTTP 404 for /api/tags` | Wrong base URL | Use `http://localhost:11434`, not `.../v1` |
| `AI endpoint returned HTTP 404 for /models` | The base URL is missing or has the wrong `/v1` root | Point at `http://host:port/v1` |
| `AI endpoint returned HTTP 401` | Missing or wrong key | Export the key or store it with `--provider-set --api-key` |
| `AI endpoint returned HTTP 404 for /chat/completions` | The server does not speak the OpenAI dialect, or the base URL has a trailing `/v1/v1` | Check the base URL; use the `custom` kind for a non-standard server |
| Model list is empty | The server exposes no `/models` route | Set the model id manually with `--model` |
| `No API key configured for <provider>` | The cloud provider has no key | Export the key or store it through the dashboard |
| Health says the AI is unreachable but scans work | The deterministic pipeline is doing the work | Check the base URL and the model id; the AI stages fall back automatically |
| Changes to `config/default.yaml` are ignored | A provider configuration was already saved in the database | `DELETE /api/providers/config` to reset to the edition defaults |
| A different config file is being loaded | `TRISHUL_CONFIG` is set | `unset TRISHUL_CONFIG` or point it at the file you want |
| Stored key stopped working | `data/.master_key` was replaced | Restore the original master key or re-enter the key |
| Very slow first response | The model is being loaded into memory | Keep the model warm; raise `ai.timeout_seconds` if needed |
