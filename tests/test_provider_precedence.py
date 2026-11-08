"""The documented provider precedence must match the code.

``docs/PROVIDERS.md`` listed the YAML defaults *above* the environment
overrides, while the code applies the environment on top of the YAML
file and lets a saved configuration win over both. An operator who
followed the documentation would have expected a saved configuration to
be overruled by an environment variable.
"""

from __future__ import annotations

import re
from pathlib import Path

from backend.app.core.config import Settings, _apply_env_overrides

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS_DOC = ROOT / "docs" / "PROVIDERS.md"


def _precedence_section() -> str:
    text = PROVIDERS_DOC.read_text(encoding="utf-8")
    start = text.index("## How the active provider is resolved")
    remainder = text[start:]
    end = remainder.find("\n---")
    return remainder[:end] if end != -1 else remainder


def test_the_documentation_lists_the_precedence_in_order():
    section = _precedence_section()
    entries = re.findall(r"^\d+\.\s+\*\*(.+?)\*\*", section, re.MULTILINE)

    assert len(entries) >= 3, "the precedence list must name every layer"
    labels = [entry.lower() for entry in entries]
    assert "saved" in labels[0], "a saved configuration wins"
    assert "environment" in labels[1], "the environment is applied on top of the YAML file"
    assert "yaml" in labels[2], "the YAML file is the lowest configuration layer"


def test_the_environment_is_documented_above_the_yaml_defaults():
    section = _precedence_section().lower()

    assert section.index("environment") < section.index("yaml")


def test_the_environment_overrides_the_yaml_defaults(monkeypatch):
    fresh = Settings()
    fresh.ai.model = "yaml-model"
    fresh.ai.base_url = "https://yaml.example/v1"

    monkeypatch.setenv("TRISHUL_AI_MODEL", "env-model")
    monkeypatch.setenv("TRISHUL_AI_BASE_URL", "https://env.example/v1")
    _apply_env_overrides(fresh)

    assert fresh.ai.model == "env-model"
    assert fresh.ai.base_url == "https://env.example/v1"


def test_a_saved_provider_configuration_wins_over_the_environment(ai_manager, storage, monkeypatch):
    monkeypatch.setenv("TRISHUL_AI_MODEL", "env-model")
    storage.set_provider_config(
        {
            "provider": "openai",
            "edition": "provider",
            "model": "saved-model",
            "base_url": "https://saved.example/v1",
            "timeout_seconds": 60,
        }
    )

    config = ai_manager.current_config()

    assert config.model == "saved-model"
    assert config.base_url == "https://saved.example/v1"
