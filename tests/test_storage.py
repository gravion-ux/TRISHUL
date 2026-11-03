"""Tests for the SQLite storage layer."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.app.models import (
    Evidence,
    Finding,
    GuideSession,
    GuideStep,
    ScanMode,
    ScanRecord,
    ScanStatus,
    Severity,
)


def _scan(scan_id: str, target: str = "example.com") -> ScanRecord:
    now = datetime.now(timezone.utc)
    return ScanRecord(
        id=scan_id,
        target=target,
        mode=ScanMode.DEEP,
        status=ScanStatus.QUEUED,
        created_at=now,
        updated_at=now,
        authorized=True,
        authorization_note="ticket-1234",
    )


def _finding(finding_id: str = "finding-abc") -> Finding:
    return Finding(
        id=finding_id,
        source="nuclei",
        category="scanner-match",
        title="Exposed admin panel",
        description="An admin panel is reachable.",
        severity=Severity.HIGH,
        confidence=80,
        baseline_confidence=70,
        asset="https://example.com/admin",
        evidence=[Evidence(source="nuclei", summary="matched", raw={})],
    )


def test_save_and_get_scan(storage):
    scan = _scan("scan-1")
    storage.save_scan(scan)
    loaded = storage.get_scan("scan-1")
    assert loaded is not None
    assert loaded.target == "example.com"
    assert loaded.authorized is True


def test_get_missing_scan_returns_none(storage):
    assert storage.get_scan("does-not-exist") is None


def test_findings_are_persisted(storage):
    scan = _scan("scan-1")
    scan.findings = [_finding()]
    storage.save_scan(scan)
    loaded = storage.get_scan("scan-1")
    assert loaded is not None
    assert len(loaded.findings) == 1
    assert loaded.findings[0].severity == Severity.HIGH


def test_same_finding_in_two_scans_is_allowed(storage):
    """Regression: the previous release used a global primary key on findings.

    Two scans of the same target produce the same finding id, which made the
    second scan fail with an integrity error.
    """
    first = _scan("scan-1")
    first.findings = [_finding("finding-shared")]
    storage.save_scan(first)

    second = _scan("scan-2")
    second.findings = [_finding("finding-shared")]
    storage.save_scan(second)

    assert storage.get_scan("scan-1") is not None
    assert storage.get_scan("scan-2") is not None
    assert len(storage.get_scan("scan-1").findings) == 1
    assert len(storage.get_scan("scan-2").findings) == 1


def test_resaving_a_scan_replaces_its_findings(storage):
    scan = _scan("scan-1")
    scan.findings = [_finding()]
    storage.save_scan(scan)
    scan.findings = []
    storage.save_scan(scan)
    loaded = storage.get_scan("scan-1")
    assert loaded is not None
    assert loaded.findings == []


def test_list_scans_is_newest_first(storage):
    storage.save_scan(_scan("scan-old"))
    storage.save_scan(_scan("scan-new"))
    ids = [scan.id for scan in storage.list_scans()]
    assert ids[0] == "scan-new"


def test_delete_scan(storage):
    storage.save_scan(_scan("scan-1"))
    assert storage.delete_scan("scan-1") is True
    assert storage.get_scan("scan-1") is None


def test_guide_roundtrip(storage):
    guide = GuideSession(
        id="guide-1",
        scan_id="scan-1",
        finding_id="finding-abc",
        steps=[GuideStep(index=0, instruction="Check the scope")],
        updated_at=datetime.now(timezone.utc),
    )
    storage.save_guide(guide)
    loaded = storage.get_guide("guide-1")
    assert loaded is not None
    assert loaded.steps[0].instruction == "Check the scope"


def test_cache_roundtrip_and_expiry(storage):
    storage.cache_set("key", {"value": 1}, ttl_seconds=60)
    assert storage.cache_get("key") == {"value": 1}
    storage.cache_set("expired", {"value": 2}, ttl_seconds=-1)
    assert storage.cache_get("expired") is None


def test_purge_expired_cache(storage):
    storage.cache_set("expired", {"value": 1}, ttl_seconds=-1)
    storage.cache_set("live", {"value": 2}, ttl_seconds=60)
    storage.purge_expired_cache()
    assert storage.cache_get("expired") is None
    assert storage.cache_get("live") is not None


def test_provider_config_roundtrip(storage):
    assert storage.get_provider_config() is None
    storage.set_provider_config({"provider": "ollama", "model": "llama3.1:8b"})
    payload = storage.get_provider_config()
    assert payload is not None
    assert payload["provider"] == "ollama"


def test_integration_crud(storage):
    storage.save_integration("demo", {"name": "demo", "base_url": "https://example.test"})
    assert storage.get_integration("demo") is not None
    assert len(storage.list_integrations()) == 1
    assert storage.delete_integration("demo") is True
    assert storage.get_integration("demo") is None


def test_chat_messages_are_persisted(storage):
    storage.save_chat_message("m1", "user", "hello", scan_id="scan-1")
    storage.save_chat_message("m2", "assistant", "hi", scan_id="scan-1")
    messages = storage.list_chat_messages("scan-1")
    assert [item["role"] for item in messages] == ["user", "assistant"]
