# TRISHUL Editions

TRISHUL ships in two editions. They are **the same codebase** with a different AI
backend: same agents, same pipeline, same tool adapters, same storage, same reports, same
security gates. The edition only decides **where the model runs** and **whose key is
used**.

```
                      +---------------------------+
                      |        TRISHUL core       |
                      |  MasterAgent + engines    |
                      |  tool adapters, storage,  |
                      |  reports, security gates  |
                      +-------------+-------------+
                                    |
                     +--------------+--------------+
                     |                             |
              +------+-------+             +-------+------+
              | TRISHUL      |             | TRISHUL      |
              | LOCAL        |             | PROVIDER     |
              | Ollama /     |             | OpenAI /     |
              | LM Studio /  |             | Anthropic /  |
              | llama.cpp    |             | Gemini /     |
              | no key       |             | compat /cust |
              |              |             | your key     |
              +--------------+             +--------------+
```

---

## When to use which

| Situation | Use |
|---|---|
| Air-gapped lab, no internet at all | **LOCAL** |
| Target data must never leave your machine | **LOCAL** |
| Client data is under a strict data-processing agreement | **LOCAL** |
| You need the best reasoning quality available | **PROVIDER** |
| You have no GPU and no patience to tune local models | **PROVIDER** |
| A large context (long PoC write-ups) matters most | **PROVIDER** |
| You want a quick install with no model download | **PROVIDER** |
| You want to try a provider without changing the engine | Both — the switch is runtime-only |

You can run both on the same host, and even in the same session: the edition is a
configuration value, not a build flag.

---

## What each edition needs

| | TRISHUL LOCAL | TRISHUL PROVIDER |
|---|---|---|
| AI runs on | Your machine | The provider's servers |
| Default provider | Ollama (`http://localhost:11434`) | OpenAI (`https://api.openai.com/v1`) |
| Default model | `llama3.1:8b` | `gpt-4o-mini` |
| API key | Never required | Required — you supply your own |
| Network after install | Fully offline | The provider endpoint must be reachable |
| Local model server | Ollama, LM Studio or llama.cpp | Not needed |
| Hardware | Enough RAM/VRAM for the model you load | Only what the scanner needs |
| Data leaving the host | Nothing | Prompts and the evidence sent for analysis |
| Key storage | n/a (optional local key) | Encrypted at rest in `data/credentials.enc` |
| Installation | `./install.sh --local` | `./install.sh` |

The four real binaries — `httpx`, `nuclei`, `ffuf`, `nmap` — are required by both
editions. The edition changes nothing about how they are executed or how their output is
treated as evidence.

---

## How the shared core stays identical

1. **One codebase, one release.** The edition is selected by configuration, never by a
   conditional import or a build flag.
2. **One provider abstraction.** Every edition talks to the same `AIProvider` interface
   through the same `AIManager`. The security engine calls `complete()` and receives
   text; it does not know or care which transport produced it.
3. **One set of gates.** Authorization, scope, SSRF, rate limiting, the binary
   allowlist and redaction are enforced in deterministic code. They run before the model
   is called, and they are identical in both editions.
4. **One deterministic fallback.** When no model is reachable, the pipeline still
   completes: the deterministic evidence score stands as `baseline_confidence`, the
   effective `confidence` equals it, `ai_adjusted` is `false`, and the health endpoint
   reports the AI as unavailable. The edition never changes what happens without AI.
5. **One storage and reporting path.** Scans, findings, evidence, guides and reports are
   stored and rendered the same way in both editions. A scan performed in LOCAL and one
   performed in PROVIDER are directly comparable.
6. **One configuration schema.** The `ai` section is identical in both editions; only
   the default `provider`, `model` and `base_url` differ.

---

## Switching between editions

### Switch at runtime (no restart)

```bash
# To PROVIDER
trishul --provider-set openai --model gpt-4o-mini --api-key 'sk-...'

# To LOCAL
trishul --provider-set ollama --model llama3.1:8b
```

Or through the API:

```bash
curl -s -X POST http://127.0.0.1:8000/api/providers/config \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"provider":"ollama","model":"llama3.1:8b","edition":"local"}'
```

The change takes effect on the next AI call. Running scans are not interrupted, and the
security engine is untouched.

### Switch by configuration file

Two ready-made configurations ship with TRISHUL:

```bash
# LOCAL edition
export TRISHUL_CONFIG=config/default.local.yaml

# PROVIDER edition
export TRISHUL_CONFIG=config/default.provider.yaml
```

`TRISHUL_CONFIG` is the highest-precedence way to point TRISHUL at a different YAML
file. The release archives `TRISHUL-LOCAL.zip` and `TRISHUL-PROVIDER.zip` ship the
matching file as `config/default.yaml`, so the edition is correct without any
environment variable.

### Switch with environment variables

```bash
export TRISHUL_EDITION=provider
export TRISHUL_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY='sk-ant-...'
```

Selecting a provider also moves the endpoint and the model to that provider's
documented defaults, so Anthropic is reached at `https://api.anthropic.com`
with `claude-3-5-sonnet-latest`. Pin `TRISHUL_AI_BASE_URL` and
`TRISHUL_AI_MODEL` yourself when you want something else — they are never
overwritten.

An explicit `TRISHUL_AI_PROVIDER` always wins over the edition default, so the
PROVIDER edition never rewrites a provider you chose yourself.

### Reset to the edition default

```bash
curl -s -X DELETE http://127.0.0.1:8000/api/providers/config -H "Authorization: Bearer $TOKEN"
```

This drops the saved provider configuration and restores the defaults from the active
YAML file. The stored key is kept.

---

## Behaviour differences you will notice

| Behaviour | LOCAL | PROVIDER |
|---|---|---|
| First response after the model changes | Slow while the model loads into memory | Fast (provider keeps the model warm) |
| Reasoning quality | Depends on the model you can run locally | Generally higher on current frontier models |
| Context size | Limited by your local server | Usually larger |
| Findings that need AI | Degraded to deterministic results if the local server is down | Degraded to deterministic results if the provider is unreachable |
| Cost | No per-request cost, only hardware | Per-request cost from the provider |
| Audit trail | Everything stays local | The prompt and evidence leave your host |

In both editions, a degraded AI never invents a verdict: the deterministic evidence
score stands and the AI is marked unavailable.

---

## Verifying which edition you are on

```bash
trishul --provider        # shows the edition, provider, model, base URL and key status
trishul --health          # shows the edition, tool status and AI reachability
curl -s http://127.0.0.1:8000/api/health | python -m json.tool
```

The health response contains `edition` (`local` or `provider`), the active provider and
model, and whether the AI is `reachable`.
