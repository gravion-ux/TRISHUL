"""Agent-level behaviour tests.

Covers the DetectionAgent, the VerificationAgent scoring and AI adjudication,
the ReasoningEngine deduplication and ranking, the PoCEngine, the GuideEngine
and the ReportAgent.

The AI is replaced with a deterministic stub so the tests never depend on a
reachable model, and the verification probes are stubbed so the tests never
open a socket.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.ai.base import AIRequest, AIResponse
from backend.app.engine.base import AgentContext
from backend.app.engine.detection import DetectionAgent
from backend.app.engine.guide import GuideEngine
from backend.app.engine.poc import PoCEngine
from backend.app.engine.reasoning import ReasoningEngine
from backend.app.engine.report import ReportAgent
from backend.app.engine.verification import VerificationAgent
from backend.app.models import (
    Evidence,
    Finding,
    GuideAction,
    ScanMode,
    ScanRecord,
    ScanStatus,
    Severity,
)
from backend.app.core.utils import utcnow


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class StubAI:
    """A deterministic stand-in for :class:`AIManager`."""

    def __init__(self, responses: list[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.requests: list[AIRequest] = []

    async def complete(self, request: AIRequest) -> AIResponse:
        self.requests.append(request)
        if not self.responses:
            raise RuntimeError("stub AI has no queued response")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return AIResponse(
            text=str(item),
            model="stub-model",
            provider="stub-provider",
            latency_ms=1,
        )


def make_finding(**overrides) -> Finding:
    """Build a Finding with sensible defaults."""
    data = {
        "id": "finding-1",
        "source": "nuclei",
        "category": "scanner-match",
        "title": "Example finding",
        "description": "Something was detected.",
        "severity": Severity.MEDIUM,
        "asset": "https://example.com/",
        "attack_surface": "example.com",
        "evidence": [Evidence(source="nuclei", summary="matched", raw={})],
    }
    data.update(overrides)
    return Finding(**data)


@pytest.fixture()
def scan() -> ScanRecord:
    now = utcnow()
    return ScanRecord(
        id="scan-test",
        target="https://example.com",
        mode=ScanMode.DEEP,
        status=ScanStatus.RUNNING,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="TEST-1234",
    )


@pytest.fixture()
def ctx(scan, storage, settings, ai_manager, integration_manager, tool_registry, adapters, scope, tmp_path):
    return AgentContext(
        scan=scan,
        settings=settings,
        storage=storage,
        ai=ai_manager,
        integrations=integration_manager,
        scope=scope,
        tools=tool_registry,
        adapters=adapters,
        scan_dir=tmp_path / "scan",
    )


PROFILE = {"host": "example.com", "url": "https://example.com"}


# ---------------------------------------------------------------------------
# DetectionAgent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_nuclei_severity_and_evidence(ctx):
    agent = DetectionAgent(ctx.storage)
    scan_result = {
        "nuclei": [
            {
                "template-id": "exposed-git",
                "matched-at": "https://example.com/.git/config",
                "info": {
                    "name": "Exposed .git directory",
                    "severity": "high",
                    "description": "A .git directory was reachable.",
                    "reference": ["https://example.org/advisory"],
                    "classification": {"cwe-id": "CWE-527"},
                },
            }
        ]
    }

    findings = await agent.run(ctx, PROFILE, {}, scan_result, {})

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "nuclei"
    assert finding.severity == Severity.HIGH
    assert finding.asset == "https://example.com/.git/config"
    assert finding.evidence and finding.evidence[0].source == "nuclei"
    assert finding.references == ["https://example.org/advisory"]
    assert finding.raw["cwe"] == "CWE-527"


@pytest.mark.asyncio
async def test_detection_nmap_risky_port_severity(ctx):
    agent = DetectionAgent(ctx.storage)
    scan_result = {
        "nmap": {
            "services": [
                {
                    "host": "example.com",
                    "port": 6379,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "redis",
                    "product": "Redis",
                    "version": "7.0.0",
                }
            ]
        }
    }

    findings = await agent.run(ctx, PROFILE, {}, scan_result, {})

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].asset == "example.com:6379"
    assert "redis" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_detection_nmap_ordinary_port_is_informational(ctx):
    agent = DetectionAgent(ctx.storage)
    scan_result = {
        "nmap": {
            "services": [
                {
                    "host": "example.com",
                    "port": 8080,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "",
                    "version": "",
                }
            ]
        }
    }

    findings = await agent.run(ctx, PROFILE, {}, scan_result, {})

    assert findings[0].severity == Severity.INFORMATIONAL


@pytest.mark.asyncio
async def test_detection_ffuf_only_reports_sensitive_paths(ctx):
    agent = DetectionAgent(ctx.storage)
    fuzz_result = {
        "ffuf": [
            {
                "url": "https://example.com/.env",
                "status": 200,
                "words": 10,
                "lines": 5,
                "length": 120,
                "mode": "directory",
                "input": {"FUZZ": ".env"},
            },
            {
                "url": "https://example.com/robots.txt",
                "status": 200,
                "words": 3,
                "lines": 2,
                "length": 40,
                "mode": "directory",
                "input": {"FUZZ": "robots.txt"},
            },
        ]
    }

    findings = await agent.run(ctx, PROFILE, {}, {}, fuzz_result)

    assert len(findings) == 1
    assert findings[0].source == "ffuf"
    assert findings[0].severity == Severity.MEDIUM
    assert ".env" in findings[0].title


@pytest.mark.asyncio
async def test_detection_ffuf_forbidden_status_is_informational(ctx):
    agent = DetectionAgent(ctx.storage)
    fuzz_result = {
        "ffuf": [
            {
                "url": "https://example.com/admin",
                "status": 403,
                "mode": "directory",
                "input": {"FUZZ": "admin"},
            }
        ]
    }

    findings = await agent.run(ctx, PROFILE, {}, {}, fuzz_result)

    assert findings[0].severity == Severity.INFORMATIONAL


@pytest.mark.asyncio
async def test_detection_technology_disclosure_is_informational(ctx):
    agent = DetectionAgent(ctx.storage)
    recon_result = {"technologies": ["Nginx", "PHP"]}

    findings = await agent.run(ctx, PROFILE, recon_result, {}, {})

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFORMATIONAL
    assert findings[0].source == "httpx"


# ---------------------------------------------------------------------------
# VerificationAgent — deterministic scoring
# ---------------------------------------------------------------------------


def _checks(**overrides) -> dict:
    checks = {
        "http_status": None,
        "http_ok": False,
        "http_blocked": False,
        "tcp_open": False,
        "asset_live": False,
        "corroborated": False,
        "active_successes": 0,
        "notes": [],
    }
    checks.update(overrides)
    return checks


def test_verification_score_uses_severity_base(ctx):
    agent = VerificationAgent(ctx.storage)

    score = agent._score(make_finding(severity=Severity.HIGH), _checks())

    # High base (55), no evidence at all, so the "no live signal" penalty (-20).
    assert score == 35


def test_verification_score_adds_positive_signals(ctx):
    agent = VerificationAgent(ctx.storage)
    finding = make_finding(
        severity=Severity.LOW,
        source="httpx",
        evidence=[
            Evidence(source="httpx", summary="one", raw={}),
            Evidence(source="verification", summary="two", raw={}),
        ],
        references=["https://example.org/advisory"],
    )

    score = agent._score(
        finding,
        _checks(corroborated=True, asset_live=True, http_ok=True, tcp_open=True),
    )

    # 25 base + 15 corroborated + 12 live + 12 http + 12 tcp + 8 evidence + 5 refs
    assert score == 89


def test_verification_score_is_clamped_to_one_hundred(ctx):
    agent = VerificationAgent(ctx.storage)
    finding = make_finding(
        severity=Severity.CRITICAL,
        source="httpx",
        evidence=[
            Evidence(source="httpx", summary="one", raw={}),
            Evidence(source="verification", summary="two", raw={}),
        ],
        references=["https://example.org/advisory"],
    )

    score = agent._score(
        finding,
        _checks(corroborated=True, asset_live=True, http_ok=True, tcp_open=True),
    )

    # 70 + 15 + 12 + 12 + 12 + 8 + 5 = 134, clamped to 100.
    assert score == 100


def test_verification_score_penalises_not_found(ctx):
    agent = VerificationAgent(ctx.storage)
    finding = make_finding(severity=Severity.HIGH, source="httpx")

    score = agent._score(finding, _checks(http_status=404))

    # 55 base - 25 (404) - 20 (no live signal)
    assert score == 10


def test_verification_score_penalises_waf_block(ctx):
    agent = VerificationAgent(ctx.storage)
    finding = make_finding(severity=Severity.HIGH, source="httpx")

    score = agent._score(finding, _checks(http_blocked=True, http_status=403))

    # 55 base - 20 (blocked) - 20 (no live signal)
    assert score == 15


def test_verification_score_penalises_nmap_without_version(ctx):
    agent = VerificationAgent(ctx.storage)
    checks = _checks(corroborated=True, asset_live=True)

    with_version = agent._score(
        make_finding(source="nmap", severity=Severity.LOW, raw={"version": "1.2.3"}), checks
    )
    without_version = agent._score(
        make_finding(source="nmap", severity=Severity.LOW, raw={}), checks
    )

    # 25 base + 15 corroborated + 12 live, minus 8 when nmap saw no banner.
    assert with_version == 52
    assert without_version == 44


def test_verification_score_is_clamped_to_zero(ctx):
    agent = VerificationAgent(ctx.storage)

    score = agent._score(
        make_finding(severity=Severity.INFORMATIONAL),
        _checks(http_status=404, http_blocked=True),
    )

    assert score == 0
    assert 0 <= score <= 100


# ---------------------------------------------------------------------------
# VerificationAgent — AI adjudication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verification_ai_verdict_overrides_severity_and_confidence(ctx, monkeypatch):
    async def fake_tcp(host, port):
        return True

    async def fake_http(_ctx, client, url):
        return 200, "ok body", False

    monkeypatch.setattr(VerificationAgent, "_tcp_probe", staticmethod(fake_tcp))
    monkeypatch.setattr(VerificationAgent, "_http_probe", staticmethod(fake_http))

    ai = StubAI(
        [
            json.dumps(
                {
                    "severity": "Critical",
                    "confidence": 91,
                    "verified": True,
                    "false_positive": False,
                    "reasoning": "Confirmed on the live asset.",
                    "remediation": "Remove the exposed directory.",
                }
            )
        ]
    )
    agent = VerificationAgent(ctx.storage, ai)
    finding = make_finding(severity=Severity.MEDIUM)
    finding.confidence = 40

    result = await agent.run(ctx, [finding], {}, {})

    assert len(result) == 1
    adjudicated = result[0]
    assert adjudicated.severity == Severity.CRITICAL
    assert adjudicated.confidence == 91
    assert adjudicated.verified is True
    assert adjudicated.ai_adjusted is True
    assert adjudicated.ai_analysis == "Confirmed on the live asset."
    # The deterministic baseline is preserved so the override stays auditable.
    assert adjudicated.baseline_confidence > 0
    assert adjudicated.baseline_confidence != adjudicated.confidence
    assert any(item.source == "ai" for item in adjudicated.evidence)


@pytest.mark.asyncio
async def test_verification_ai_false_positive_downgrades(ctx, monkeypatch):
    async def fake_tcp(host, port):
        return False

    async def fake_http(_ctx, client, url):
        return 200, "ok body", False

    monkeypatch.setattr(VerificationAgent, "_tcp_probe", staticmethod(fake_tcp))
    monkeypatch.setattr(VerificationAgent, "_http_probe", staticmethod(fake_http))

    ai = StubAI(
        [
            json.dumps(
                {
                    "severity": "Informational",
                    "confidence": 5,
                    "verified": False,
                    "false_positive": True,
                    "reasoning": "This is the application's normal home page.",
                }
            )
        ]
    )
    agent = VerificationAgent(ctx.storage, ai)
    finding = make_finding(severity=Severity.HIGH)

    result = await agent.run(ctx, [finding], {}, {})

    adjudicated = result[0]
    assert adjudicated.verified is False
    assert adjudicated.severity == Severity.INFORMATIONAL
    assert adjudicated.confidence <= 15
    assert "likely-false-positive" in adjudicated.category


@pytest.mark.asyncio
async def test_verification_ai_failure_keeps_deterministic_baseline(ctx, monkeypatch):
    async def fake_tcp(host, port):
        return False

    async def fake_http(_ctx, client, url):
        return 200, "ok body", False

    monkeypatch.setattr(VerificationAgent, "_tcp_probe", staticmethod(fake_tcp))
    monkeypatch.setattr(VerificationAgent, "_http_probe", staticmethod(fake_http))

    ai = StubAI([RuntimeError("provider unreachable")])
    agent = VerificationAgent(ctx.storage, ai)
    finding = make_finding(severity=Severity.HIGH)

    result = await agent.run(ctx, [finding], {}, {})

    adjudicated = result[0]
    assert adjudicated.ai_adjusted is False
    assert adjudicated.confidence == adjudicated.baseline_confidence
    assert ctx.ai_errors, "the AI failure must be recorded for diagnostics"


@pytest.mark.asyncio
async def test_verification_without_ai_does_not_crash(ctx, monkeypatch):
    async def fake_tcp(host, port):
        return False

    async def fake_http(_ctx, client, url):
        return None, "", False

    monkeypatch.setattr(VerificationAgent, "_tcp_probe", staticmethod(fake_tcp))
    monkeypatch.setattr(VerificationAgent, "_http_probe", staticmethod(fake_http))

    agent = VerificationAgent(ctx.storage, None)
    finding = make_finding(severity=Severity.LOW)

    result = await agent.run(ctx, [finding], {}, {})

    assert result[0].confidence == result[0].baseline_confidence
    assert result[0].ai_adjusted is False


# ---------------------------------------------------------------------------
# ReasoningEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reasoning_deterministic_dedup_merges_same_title_and_asset(ctx):
    agent = ReasoningEngine(ctx.storage, None)
    first = make_finding(id="a", title="Exposed .git directory", confidence=40)
    second = make_finding(id="b", title="exposed  .git   directory", confidence=70)
    second.evidence = [Evidence(source="other", summary="second source", raw={})]

    result = await agent.run(ctx, [first, second])

    assert len(result) == 1
    merged = result[0]
    assert merged.confidence == 70
    assert len(merged.evidence) == 2


@pytest.mark.asyncio
async def test_reasoning_deterministic_dedup_keeps_more_severe(ctx):
    agent = ReasoningEngine(ctx.storage, None)
    low = make_finding(id="a", title="Same title", severity=Severity.LOW)
    critical = make_finding(id="b", title="same title", severity=Severity.CRITICAL)

    result = await agent.run(ctx, [low, critical])

    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_reasoning_ai_semantic_dedup(ctx):
    ai = StubAI(
        [
            json.dumps(
                {
                    "duplicates": [{"keep": "a", "merge": ["b"]}],
                    "false_positives": [],
                    "notes": "same underlying issue",
                }
            )
        ]
    )
    agent = ReasoningEngine(ctx.storage, ai)
    first = make_finding(id="a", title="Exposed .git directory")
    second = make_finding(
        id="b",
        title="Version control metadata accessible",
        evidence=[Evidence(source="other", summary="second source", raw={})],
    )

    result = await agent.run(ctx, [first, second])

    assert len(result) == 1
    assert result[0].id == "a"
    assert len(result[0].evidence) == 2


@pytest.mark.asyncio
async def test_reasoning_ai_false_positive_triage(ctx):
    ai = StubAI(
        [json.dumps({"duplicates": [], "false_positives": ["b"]})]
    )
    agent = ReasoningEngine(ctx.storage, ai)
    first = make_finding(id="a", title="Real issue", severity=Severity.HIGH, confidence=80)
    second = make_finding(id="b", title="Expected directory", severity=Severity.MEDIUM, confidence=60)

    result = await agent.run(ctx, [first, second])

    by_id = {item.id: item for item in result}
    assert by_id["b"].severity == Severity.INFORMATIONAL
    assert by_id["b"].verified is False
    assert by_id["b"].confidence <= 15
    assert "likely-false-positive" in by_id["b"].category


@pytest.mark.asyncio
async def test_reasoning_ranking_orders_by_severity_then_confidence(ctx):
    agent = ReasoningEngine(ctx.storage, None)
    findings = [
        make_finding(id="low", title="Low", severity=Severity.LOW, confidence=90),
        make_finding(id="critical", title="Critical", severity=Severity.CRITICAL, confidence=20),
        make_finding(id="medium", title="Medium", severity=Severity.MEDIUM, confidence=50),
        make_finding(id="high", title="High", severity=Severity.HIGH, confidence=10),
    ]

    result = await agent.run(ctx, findings)

    assert [item.id for item in result] == ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# PoCEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poc_port_finding_uses_nmap_and_is_non_destructive(ctx):
    agent = PoCEngine(ctx.storage, None)
    finding = make_finding(
        source="nmap",
        asset="example.com:6379",
        severity=Severity.HIGH,
        title="Open service redis on example.com:6379",
    )

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "deterministic"
    assert "nmap" in bundle.request_example
    assert "6379" in bundle.request_example
    assert bundle.screenshot_guide
    assert bundle.video_script
    assert "Steps to Reproduce" in bundle.bounty_report

    lowered = " ".join(bundle.steps_to_reproduce).lower()
    for forbidden in ("delete", "rm -rf", "brute force", "exploit payload", "drop table"):
        assert forbidden not in lowered


@pytest.mark.asyncio
async def test_poc_url_finding_uses_read_only_curl(ctx):
    agent = PoCEngine(ctx.storage, None)
    finding = make_finding(asset="https://example.com/.env", severity=Severity.MEDIUM)

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.request_example.startswith("curl -isk")
    assert "-X POST" not in bundle.request_example
    assert "-X DELETE" not in bundle.request_example


@pytest.mark.asyncio
async def test_poc_ai_bundle_is_preferred_when_available(ctx):
    ai = StubAI(
        [
            json.dumps(
                {
                    "steps_to_reproduce": ["Open the URL in a clean browser session."],
                    "request_example": "curl -isk https://example.com/.env",
                    "response_example": "HTTP/1.1 200 OK",
                    "impact": "Configuration disclosure.",
                    "remediation": "Remove the file from the deployment.",
                    "screenshot_guide": ["Capture the response."],
                    "video_script": ["Show the request."],
                }
            )
        ]
    )
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding(asset="https://example.com/.env")

    result = await agent.run(ctx, [finding])

    bundle = result[0].poc
    assert bundle is not None
    assert bundle.generated_by == "ai"
    # The deterministic steps stay the backbone and the validated AI step is
    # appended to them -- the AI never replaces the safe bundle.
    assert any("approved scope" in step for step in bundle.steps_to_reproduce)
    assert "Open the URL in a clean browser session." in bundle.steps_to_reproduce
    # The bounty report is rendered from the steps that are actually published.
    assert "Steps to Reproduce" in bundle.bounty_report
    assert "Open the URL in a clean browser session." in bundle.bounty_report


@pytest.mark.asyncio
async def test_poc_falls_back_to_deterministic_when_ai_returns_nothing(ctx):
    ai = StubAI([json.dumps({"steps_to_reproduce": []})])
    agent = PoCEngine(ctx.storage, ai)
    finding = make_finding(asset="https://example.com/.env")

    result = await agent.run(ctx, [finding])

    assert result[0].poc is not None
    assert result[0].poc.generated_by == "deterministic"


# ---------------------------------------------------------------------------
# GuideEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guide_prepare_creates_steps(ctx):
    agent = GuideEngine(ctx.storage, None)
    finding = make_finding()
    finding.poc = PoCEngine(ctx.storage, None)._deterministic_bundle(ctx, finding)

    result = await agent.prepare(ctx, [finding])

    steps = result[0].guide_steps
    assert steps
    assert steps[0].status == "active"
    assert all(step.status == "pending" for step in steps[1:])
    assert all(step.hint for step in steps)


@pytest.mark.asyncio
async def test_guide_start_and_advance(ctx):
    agent = GuideEngine(ctx.storage, None)
    finding = make_finding()
    finding.poc = PoCEngine(ctx.storage, None)._deterministic_bundle(ctx, finding)
    await agent.prepare(ctx, [finding])
    ctx.scan.findings = [finding]

    guide = await agent.start(ctx, finding.id)
    assert guide.status == "active"
    assert ctx.storage.get_guide(guide.id) is not None

    total = len(guide.steps)
    for _ in range(total):
        guide = await agent.advance(ctx, guide, GuideAction.NEXT)

    assert guide.current_step >= total
    assert guide.status == "completed"


@pytest.mark.asyncio
async def test_guide_hint_uses_ai_when_available(ctx):
    ai = StubAI([json.dumps({"hint": "Check the engagement ticket first."})])
    agent = GuideEngine(ctx.storage, ai)
    finding = make_finding()
    finding.poc = PoCEngine(ctx.storage, None)._deterministic_bundle(ctx, finding)
    await agent.prepare(ctx, [finding])
    ctx.scan.findings = [finding]

    guide = await agent.start(ctx, finding.id)
    guide = await agent.advance(ctx, guide, GuideAction.HINT)

    assert guide.steps[0].hint == "Check the engagement ticket first."
    assert any(item.startswith("hint:") for item in guide.history)


@pytest.mark.asyncio
async def test_guide_hint_falls_back_to_deterministic_hint(ctx):
    agent = GuideEngine(ctx.storage, None)
    finding = make_finding()
    finding.poc = PoCEngine(ctx.storage, None)._deterministic_bundle(ctx, finding)
    await agent.prepare(ctx, [finding])
    ctx.scan.findings = [finding]

    guide = await agent.start(ctx, finding.id)
    original = guide.steps[0].hint
    guide = await agent.advance(ctx, guide, GuideAction.HINT)

    assert guide.steps[0].hint == original


@pytest.mark.asyncio
async def test_guide_start_rejects_unknown_finding(ctx):
    agent = GuideEngine(ctx.storage, None)

    with pytest.raises(ValueError):
        await agent.start(ctx, "does-not-exist")


# ---------------------------------------------------------------------------
# ReportAgent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_agent_writes_every_format(ctx):
    finding = make_finding()
    finding.poc = PoCEngine(ctx.storage, None)._deterministic_bundle(ctx, finding)
    ctx.scan.findings = [finding]

    agent = ReportAgent(ctx.storage, None)
    paths = await agent.run(ctx)

    assert set(paths) == {"json", "markdown", "html", "bug_bounty"}
    for path in paths.values():
        assert Path(path).exists(), f"{path} was not written"
    assert ctx.scan.artifacts["executive_summary"] == ""


@pytest.mark.asyncio
async def test_report_agent_uses_ai_summary(ctx):
    ai = StubAI(["The target was assessed with a deep scan. One high severity issue was found."])
    finding = make_finding()
    ctx.scan.findings = [finding]

    agent = ReportAgent(ctx.storage, ai)
    await agent.run(ctx)

    assert "deep scan" in ctx.scan.artifacts["executive_summary"]
