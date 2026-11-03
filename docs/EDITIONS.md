# TRISHUL — Editions

TRISHUL ships as two editions. They are **the same codebase** with a
different default configuration and a different AI backend — not two
products, and not a fork.

|  | TRISHUL LOCAL | TRISHUL PROVIDER |
|---|---|---|
| AI backend | Ollama, LM Studio, llama.cpp | OpenAI, Anthropic, Gemini, OpenAI-compatible, custom |
| Cloud key required | **No** | Yes, for the cloud providers |
| Works offline | **Yes**, after dependencies and a model are installed | No — the model is a remote service |
| Data leaves the machine | Only to the target | Target **and** the model provider |
| Default provider | `ollama` | `openai` |
| Default model | `llama3.1:8b` | `gpt-4o-mini` |
| Archive | `TRISHUL-LOCAL.zip` | `TRISHUL-PROVIDER.zip` |
| Full source, edition selectable | `TRISHUL-SOURCE.zip` | `TRISHUL-SOURCE.zip` |

---

## 1. Why two editions at all

A security tool is often used in situations where the operator cannot send
the target's data to a third party: a pentest under a strict NDA, an internal
assessment, an air-gapped lab, a bug bounty where the program forbids
uploading target content.

TRISHUL LOCAL serves that case. The model runs on the operator's own machine
and nothing but the scan traffic and the target's own responses touch the
network.

TRISHUL PROVIDER serves the case where a frontier model materially improves
the analysis and the operator is allowed to use one.

The engine does not know which edition it is running in. A finding is scored
the same way in both; only the adjudicator differs.

---

## 2. TRISHUL LOCAL

### Requirements

- A model server: Ollama (recommended), LM Studio, or llama.cpp.
- At least one model pulled and loaded.
- The four scanners: `httpx`, `nmap`, `nuclei`, `ffuf`.

### Setup

```bash
./install.sh
ollama serve
ollama pull llama3.1:8b
trishul --provider-set ollama --model llama3.1:8b
trishul --health
```

### What works offline

Once the tools and a model are installed, the whole system runs without an
internet connection:

- Recon, scanning, fuzzing and detection are local tools.
- Verification probes the target directly.
- The AI adjudicates against the local model server.
- Reports are rendered locally.

The only network traffic is to the target itself.

### Model guidance

| Model | Notes |
|---|---|
| `llama3.1:8b` | The default. Good balance of quality and speed. |
| `llama3.1:70b` | Better judgement, needs real hardware. |
| `qwen2.5-coder` | Good at structured output. |
| `mistral` | Fast, adequate for triage. |
| Any GGUF via llama.cpp | Bring your own. |

A model that follows JSON instructions well matters more than raw
intelligence, because the agents parse structured verdicts. If a model
struggles to return valid JSON, use a smaller, more instruct-tuned model
rather than a larger base model.

---

## 3. TRISHUL PROVIDER

### Setup

```bash
./install.sh
export OPENAI_API_KEY="sk-..."        # or ANTHROPIC_API_KEY, or GEMINI_API_KEY
trishul --provider-set openai --model gpt-4o-mini
trishul --health
```

### Choosing a provider

See [PROVIDERS.md](PROVIDERS.md) for the full guide. The short version:

| You want | Use |
|---|---|
| The strongest analysis | `anthropic` with a Claude Sonnet model |
| A cheap, fast triage | `openai` with `gpt-4o-mini`, or `gemini` with `gemini-2.0-flash` |
| A corporate gateway or vLLM | `openai-compatible` with your base URL |
| Multiple providers side by side | Switch any time from Provider Settings |

### Data handling

When you use a cloud provider, the prompt sent to the model contains the
findings: titles, severities, evidence summaries, asset URLs and the raw tool
output for that finding. Treat the model provider as a third party in the
engagement and check that your scope agreement permits it.

If it does not, use TRISHUL LOCAL. Nothing in the engine requires a cloud
model.

---

## 4. Switching editions

The edition is configuration, not a build. You can move between them at any
time without reinstalling anything.

```bash
# To LOCAL
trishul --provider-set ollama --model llama3.1:8b --edition local

# To PROVIDER
trishul --provider-set openai --model gpt-4o-mini --edition provider \
        --api-key "$OPENAI_API_KEY"
```

Or in the dashboard: **Provider Settings → Edition**.

The engine reads the active configuration at call time, so a switch takes
effect on the next stage of a running scan. A scan that started under one
edition finishes with whichever provider is active when each agent asks for
its verdict, and every finding records which adjudicated it.

### Environment overrides

For CI and headless deployments:

```bash
TRISHUL_EDITION=provider
TRISHUL_AI_PROVIDER=anthropic
TRISHUL_AI_MODEL=claude-3-5-sonnet-latest
ANTHROPIC_API_KEY=sk-ant-...
```

These take precedence over `config/default.yaml` but not over a provider
configuration saved in the database. Use the API or the CLI to clear the
stored configuration if you want the environment to be the only source.

---

## 5. What is identical in both editions

Everything that produces the evidence:

- The tool adapters and their argument construction.
- The scope and authorization policy.
- The detection rules and severity mapping.
- The deterministic confidence formula.
- The report formats.
- The dashboard, the CLI and the API.

What differs is only **who or what performs the final adjudication**:

|  | LOCAL | PROVIDER |
|---|---|---|
| Adjudicator | A local model server | A remote model service |
| Baseline confidence | Always computed | Always computed |
| AI override | Optional, recorded | Optional, recorded |
| Unreachable model | Deterministic score stands (default) | Deterministic score stands (default) |

The `baseline_confidence` field is present in both editions for the same
reason: an auditor must be able to see what the evidence said before the
model had an opinion.

---

## 6. The three archives

All three archives are built from one source tree, so they never drift.

### `TRISHUL-LOCAL.zip`

The full source with the LOCAL edition as the default: `ai.provider` is
`ollama`, `ai.edition` is `local`. Use it when you want a working install
without editing any configuration.

### `TRISHUL-PROVIDER.zip`

The full source with the PROVIDER edition as the default: `ai.provider` is
`openai`, `ai.edition` is `provider`. Use it when you are wiring the tool
into a cloud-backed deployment.

### `TRISHUL-SOURCE.zip`

The full source with both editions intact and the edition selectable at
runtime. This is the archive to publish, fork or contribute to.

Each archive contains the complete project — backend, frontend, CLI, tests,
migrations and documentation — plus a prebuilt `frontend/dist/` so the
dashboard works without a Node toolchain. The archives contain **no**
credentials, no databases and no scan output.

---

## 7. Choosing between them

| Your situation | Edition |
|---|---|
| NDA forbids sending target data to a third party | **LOCAL** |
| Air-gapped lab | **LOCAL** |
| Internal assessment, company policy allows a cloud LLM | **PROVIDER** |
| Bug bounty with a large model allowance | **PROVIDER** |
| You want the best available analysis and can share findings | **PROVIDER** |
| You are unsure | **LOCAL**, then switch when you understand the policy |

You can switch later without reinstalling, and without losing your scan
history.
