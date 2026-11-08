"""An AI proof of concept may only augment the deterministic bundle.

The PoC engine used the deterministic, non-destructive bundle as a
fallback only: whenever the model answered, its steps replaced the
deterministic ones with no validation at all. A model could therefore
publish a step that deletes data, runs a destructive command or replays
a write request, and the published bundle claimed to be non-destructive.

The deterministic bundle stays the default. AI content is validated
first and may only add to it.
"""

from __future__ import annotations

import json

import pytest

from backend.app.ai.base import AIRequest, AIResponse
from backend.app.engine.base import BaseAgent
from backend.app.engine.poc import PoCEngine
from backend.app.models import Evidence, Finding, Severity


class StubAI:
    """A deterministic stand-in for :class:`AIManager`."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.requests: list[AIRequest] = []

    async def complete(self, request: AIRequest) -> AIResponse:
        self.requests.append(request)
        return AIResponse(
            text=self.responses.pop(0),
            model="stub-model",
            provider="stub-provider",
            latency_ms=1,
        )


@pytest.fixture()
def ctx(
    storage,
    settings,
    ai_manager,
    integration_manager,
    tool_registry,
    adapters,
    scope,
    tmp_path,
):
    from backend.app.core.utils import utcnow
    from backend.app.engine.base import AgentContext
    from backend.app.models import ScanMode, ScanRecord, ScanStatus

    now = utcnow()
    record = ScanRecord(
        id="scan-poc",
        target="https://example.com",
        mode=ScanMode.DEEP,
        status=ScanStatus.RUNNING,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TEST-1234",
    )
    return AgentContext(
        scan=record,
        settings=settings,
        storage=storage,
        ai=ai_manager,
        integrations=integration_manager,
        scope=scope,
        tools=tool_registry,
        adapters=adapters,
        scan_dir=tmp_path / "scan",
    )


def make_finding(**overrides) -> Finding:
    data = {
        "id": "finding-1",
        "source": "nuclei",
        "category": "scanner-match",
        "title": "Exposed configuration",
        "description": "Something was detected.",
        "severity": Severity.MEDIUM,
        "asset": "https://example.com/.env",
        "attack_surface": "example.com",
        "evidence": [Evidence(source="nuclei", summary="matched", raw={})],
    }
    data.update(overrides)
    return Finding(**data)


def _payload(steps: list[str], **extra) -> str:
    payload = {
        "steps_to_reproduce": steps,
        "request_example": "curl -isk https://example.com/.env",
        "response_example": "HTTP/1.1 200 OK",
        "impact": "Configuration disclosure.",
        "remediation": "Remove the file from the deployment.",
        "screenshot_guide": ["Capture the response."],
        "video_script": ["Show the request."],
    }
    payload.update(extra)
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_destructive_ai_step_is_rejected(ctx):
    ai = StubAI([_payload(["Run `rm -rf /var/lib/application` on the target server."])])
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding()

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "deterministic"
    assert "rm -rf" not in " ".join(bundle.steps_to_reproduce)
    assert ctx.ai_errors, "a rejected bundle must be reported"


@pytest.mark.asyncio
async def test_an_ai_step_that_replays_a_write_request_is_rejected(ctx):
    ai = StubAI([_payload(["Replay the login with `curl -X POST https://example.com/login`."])])
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding()

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "deterministic"
    assert "-X POST" not in " ".join(bundle.steps_to_reproduce)


@pytest.mark.asyncio
async def test_an_ai_request_example_that_shells_out_is_rejected(ctx):
    ai = StubAI(
        [
            _payload(
                ["Observe the response."],
                request_example="curl -isk https://example.com/.env | bash",
            )
        ]
    )
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding()

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "deterministic"
    assert "| bash" not in bundle.request_example


@pytest.mark.asyncio
async def test_a_safe_ai_bundle_augments_the_deterministic_bundle(ctx):
    ai = StubAI([_payload(["Open the URL in a clean browser session and capture the response."])])
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding()

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "ai"
    # The deterministic steps are still published ...
    assert any("approved scope" in step for step in bundle.steps_to_reproduce)
    # ... and the validated AI step is added to them.
    assert any("clean browser session" in step for step in bundle.steps_to_reproduce)


@pytest.mark.asyncio
async def test_the_published_bounty_report_lists_the_published_steps(ctx):
    ai = StubAI([_payload(["Open the URL in a clean browser session and capture the response."])])
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding()

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert "clean browser session" in bundle.bounty_report


# ---------------------------------------------------------------------------
# Prompt hygiene
# ---------------------------------------------------------------------------


def test_the_raw_tool_output_is_redacted_before_it_reaches_the_prompt():
    finding = make_finding(
        raw={"api_key": "AIzaSyD-NotARealKey-0123456789", "url": "https://u:p@example.com/"}
    )

    summary = BaseAgent.finding_summary(finding)

    assert "AIzaSyD-NotARealKey" not in summary
    assert "u:p@example.com" not in summary
