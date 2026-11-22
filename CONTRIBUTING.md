# Contributing to TRISHUL

Thanks for helping! **TRISHUL** is an AI-powered security testing
platform that runs **only against explicitly authorized scope**. Every
scan target must be in scope before a test runs — that enforcement is
the product's core promise, and contributions must never weaken it.

## Ground rules

- **Authorized scope only — hard rule.** No feature may scan, probe or
  authenticate against a target that is not in the engagement's defined
  scope. If a change makes scope checks optional, it will not be merged.
- **Non-destructive by default.** Checks validate and report; they do
  not exploit beyond the minimum proof needed, and never delete or
  alter target data.
- **Secrets stay out.** No real credentials, tokens or target data in
  code, tests, fixtures or reports — use the sample data under `data/`.

## Development setup

Requires Python 3.11 or newer.

```bash
git clone https://github.com/gravion-ux/TRISHUL.git
cd TRISHUL
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

## Running the tests

```bash
python -m pytest            # full suite (config in pytest.ini, tests/ )
python -m pytest tests -q   # quiet mode
```

The suite currently collects 330+ tests across the backend, CLI and
plugin layers. All tests run offline against fixtures and the local
test app — CI must never need a live external target.

## Project layout

- `backend/` — FastAPI service (API, scope enforcement, scan engine)
- `cli/` — command-line interface
- `plugins/` — scan/check plugins
- `frontend/` — web UI assets
- `config/`, `data/` — configuration and sample data
- `tests/` — pytest suite

## Adding a plugin or check

1. Implement it under `plugins/` following the existing plugin
   interface; declare the scope it needs and the evidence it returns.
2. Add tests under `tests/` proving: in-scope target produces the
   expected finding, and an **out-of-scope target is refused** — the
   refusal test is mandatory.
3. Document the plugin in `docs/` and the README's plugin list.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`, `fix/<short-name>`
   or `plugin/<plugin-name>`.
2. Run the full suite locally — it must pass.
3. Open the PR against `main` with: what changed, why, and the tests
   (including the out-of-scope refusal test, where relevant).
4. CI must be green (Python 3.11 and 3.12).
5. One logical change per PR.
