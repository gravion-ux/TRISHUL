# TRISHUL — AI providers

TRISHUL ships one engine and several interchangeable AI backends. The engine
never imports a provider directly: it asks `AIManager` for a completion, and
`AIManager` resolves the active provider at that moment. Switching provider
therefore never touches the engine, never restarts a scan and never
invalidates a running job.

---

## 1. Supported providers

| Provider | Kind | Edition | Default base URL | Default model | Key required |
|---|---|---|---|---|---|
| Ollama | `ollama` | Local | `http://localhost:11434` | `llama3.1:8b` | No |
| LM Studio | `lmstudio` | Local | `http://localhost:1234/v1` | `local-model` | No |
| llama.cpp server | `llamacpp` | Local | `http://localhost:8080/v1` | `local-model` | No |
| OpenAI | `openai` | Provider | `https://api.openai.com/v1` | `gpt-4o-mini` | Yes |
| Anthropic | `anthropic` | Provider | `https://api.anthropic.com` | `claude-3-5-sonnet-latest` | Yes |
| Google Gemini | `gemini` | Provider | `https://generativelanguage.googleapis.com` | `gemini-2.0-flash` | Yes |
| OpenAI-compatible | `openai-compatible` | Provider | `http://localhost:8000/v1` | `local-model` | No |
| Custom adapter | `custom` | Provider | `http://localhost:8080/v1` | `custom-model` | No |

`openai`, `lmstudio`, `llamacpp`, `openai-compatible` and `custom` all speak
the OpenAI `/chat/completions` dialect, so they share one implementation.

---

## 2. Local providers

### Ollama

```bash
ollama serve
ollama pull llama3.1:8b
```

```bash
trishul --provider-set ollama --model llama3.1:8b --base-url http://localhost:11434
```

Or in the dashboard: **Provider Settings → Ollama → Test connection**.

Ollama has two API shapes. TRISHUL uses the native `/api/chat` endpoint for
Ollama itself and the OpenAI-compatible `/v1` endpoint for everything else.

### LM Studio

Open **Developer / Local Server** in LM Studio, load a model, and note the
port (default `1234`). The base URL must include the `/v1` suffix:

```
http://localhost:1234/v1
```

### llama.cpp

```bash
llama-server -m ./models/model.gguf --port 8080
```

```
http://localhost:8080/v1
```

---

## 3. Cloud providers

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
trishul --provider-set openai --model gpt-4o-mini
```

The key can come from the environment or from the encrypted credential store.
Storing it in TRISHUL is the better choice for a dashboard deployment; the
environment variable is better for CI and headless use.

### Anthropic

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
trishul --provider-set anthropic --model claude-3-5-sonnet-latest
```

TRISHUL calls the Messages API at `{base_url}/v1/messages` with the
`x-api-key` header and the `anthropic-version` header.

### Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
trishul --provider-set gemini --model gemini-2.0-flash
```

`GOOGLE_API_KEY` is also accepted. TRISHUL calls
`{base_url}/v1beta/models/{model}:generateContent`.

---

## 4. OpenAI-compatible and custom endpoints

Any server that implements `POST /v1/chat/completions` works:

- vLLM
- Ollama's `/v1` endpoint
- LiteLLM
- OpenRouter
- Text Generation Inference (TGI)
- A corporate gateway

```bash
trishul --provider-set openai-compatible \
  --base-url https://my-gateway.internal/v1 \
  --model my-model \
  --api-key "$MY_GATEWAY_TOKEN"
```

TRISHUL sends the standard headers (`Authorization: Bearer <key>` when a key
is set), the `model`, `messages`, `temperature` and `max_tokens`.

### JSON mode

When an agent needs structured output, it requests JSON mode. TRISHUL then
adds `"response_format": {"type": "json_object"}` and instructs the model to
return a single JSON object. Some servers reject that field; if yours does,
either drop the field in front of it or leave `ai.fail_open` on so the
deterministic path takes over.

### Adding a brand-new dialect

A new API shape needs one new file in `backend/app/ai/providers/` that
implements the `AIProvider` protocol, plus one branch in
`AIManager.build_provider()`. Nothing else in the codebase changes — the
engine, the agents and the dashboard are all provider-agnostic.

---

## 5. Configuration precedence

The active configuration is resolved at call time:

1. **Database** — what you saved in Provider Settings or with
   `--provider-set`.
2. **`config/default.yaml`** — the `ai:` section.
3. **Environment** — the last word for headless and CI use.

| Variable | Effect |
|---|---|
| `TRISHUL_EDITION` | `local` or `provider`. |
| `TRISHUL_AI_PROVIDER` | Provider kind, e.g. `ollama`. |
| `TRISHUL_AI_MODEL` | Model id. |
| `TRISHUL_AI_BASE_URL` | Base URL. |
| `TRISHUL_AI_API_KEY` | Generic key for `openai-compatible` and `custom`. |
| `TRISHUL_AI_TIMEOUT` | Request timeout in seconds. |

Provider-specific keys are also read directly:

| Provider | Environment variables |
|---|---|
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY`, `GOOGLE_API_KEY` |
| Ollama | `OLLAMA_API_KEY` (optional) |
| LM Studio | `LMSTUDIO_API_KEY` (optional) |
| llama.cpp | `LLAMACPP_API_KEY` (optional) |
| OpenAI-compatible / Custom | `OPENAI_API_KEY`, `TRISHUL_AI_API_KEY` |

The key is resolved the same way: **encrypted store first, environment
second**.

---

## 6. Secure credential storage

When you save a key in the dashboard or pass `--api-key`, TRISHUL:

1. Encrypts it with Fernet and writes it to `data/credentials.enc`.
2. Stores the master key in `data/.master_key` with `0600` permissions — or
   takes it from `TRISHUL_MASTER_KEY` if you prefer to manage it yourself.
3. Never writes the key into the SQLite database, a log line, a report or an
   API response.

The API returns only a hint:

```json
{ "has_api_key": true, "api_key_hint": "sk-t…4f9a" }
```

> **Back up `data/.master_key` together with `data/credentials.enc`.** Without
> the master key the encrypted credentials cannot be decrypted. Losing it
> means re-entering every key; it does not mean losing your scan history.

---

## 7. Testing a connection

From the dashboard, **Provider Settings → Test connection** calls the same
code path the engine uses and reports:

- Whether the endpoint answered.
- The latency in milliseconds.
- The models the endpoint advertises, when it exposes a model list.
- The error, when it does not.

From the CLI:

```bash
trishul --health
```

The health report includes the AI section: provider, model, whether a key is
configured and whether the endpoint is reachable.

---

## 8. Model discovery

Providers that expose a model list are queried automatically:

| Provider | Endpoint |
|---|---|
| Ollama | `GET /api/tags` |
| OpenAI and compatible | `GET /v1/models` |
| Anthropic | `GET /v1/models` |
| Gemini | `GET /v1beta/models` |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/providers/models?provider=ollama"
```

If discovery fails, type the model id by hand — TRISHUL works with any model
id the endpoint accepts.

---

## 9. What the AI is allowed to do

TRISHUL gives the model **full authority over the analysis** and **no
authority over the policy**.

The model may:

- Set the final severity of a finding.
- Set the final confidence score.
- Decide whether a finding is verified.
- Judge a finding a false positive.
- Write the reproduction steps, impact and remediation.
- Produce the executive summary and the interactive guide.

The model may **not**:

- Widen the scan scope or authorize a target.
- Run a tool, a command or a request.
- Change a rate limit or a request budget.
- Produce a weaponised payload or a destructive step.
- Bypass the scope policy.

Every AI override is recorded. The deterministic score computed from the
evidence stays on the finding as `baseline_confidence`, and the model's
reasoning is stored in `ai_analysis`, so an override is always auditable.

---

## 10. When no model is reachable

`ai.fail_open` is `true` by default. If the model server is down or the key
is missing:

- The scan continues using the deterministic evidence score.
- The chat panel answers with a clear "AI is not reachable" message rather
  than pretending.
- The report records that the AI was unavailable.

Set `ai.fail_open: false` to make an unreachable model a hard error instead.
This is useful in CI, where a silently unverified scan is worse than a failed
one.

---

## 11. Troubleshooting

**"No API key configured"** — the provider requires a key and none was found.
Set it in Provider Settings, pass `--api-key`, or export the provider's
environment variable.

**"Connection refused"** — the model server is not running. For Ollama:
`ollama serve`. For LM Studio: start the local server. For llama.cpp: start
`llama-server`.

**"Model not found"** — pull the model (`ollama pull llama3.1:8b`) or pick a
different id from the discovered list.

**"404 on /v1/chat/completions"** — the base URL is wrong. For OpenAI it
must end in `/v1`; for LM Studio and llama.cpp it must end in `/v1` too.
TRISHUL does not append the path for you, because every server disagrees
about where it belongs.

**"400 invalid response_format"** — the endpoint does not support JSON mode.
See [Custom endpoints](#4-openai-compatible-and-custom-endpoints).

**Everything is slow** — raise `ai.timeout_seconds` for a large model, or
pick a smaller one. A local 30B model on CPU will be slow no matter what.
