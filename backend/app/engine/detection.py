"""DetectionAgent — turns raw tool output into structured findings."""

from __future__ import annotations

from typing import Any

from backend.app.core.utils import stable_id
from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import Evidence, Finding, Severity


class DetectionAgent(BaseAgent):
    """Normalises nuclei, nmap and ffuf output into :class:`Finding` objects.

    Detection is deterministic: it only records what the tools actually
    observed. Judgement about whether a finding is real happens later, in
    the VerificationAgent.
    """

    name = "DetectionAgent"

    RISKY_PORTS: dict[int, Severity] = {
        21: Severity.MEDIUM,
        23: Severity.HIGH,
        2375: Severity.CRITICAL,
        27017: Severity.HIGH,
        6379: Severity.HIGH,
        9200: Severity.HIGH,
        5601: Severity.MEDIUM,
        11211: Severity.HIGH,
        3389: Severity.MEDIUM,
        5900: Severity.MEDIUM,
        6379: Severity.HIGH,
        1433: Severity.HIGH,
        1521: Severity.LOW,
        2049: Severity.MEDIUM,
    }

    SENSITIVE_HINTS = (
        ".env",
        ".git",
        ".svn",
        ".hg",
        "admin",
        "backup",
        "config",
        "phpinfo",
        "swagger",
        "api-docs",
        "actuator",
        "graphql",
        "wp-config",
        "id_rsa",
        "credentials",
        "dump",
    )

    async def run(
        self,
        ctx: AgentContext,
        profile: dict[str, str],
        recon_result: dict[str, Any],
        scan_result: dict[str, Any],
        fuzz_result: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._from_nuclei(profile, scan_result))
        findings.extend(self._from_nmap(profile, scan_result))
        findings.extend(self._from_ffuf(profile, fuzz_result))
        findings.extend(self._from_recon(profile, recon_result))
        return findings

    # -- nuclei ------------------------------------------------------------

    def _from_nuclei(self, profile: dict[str, str], scan_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for item in scan_result.get("nuclei", []) or []:
            info = item.get("info") or {}
            title = info.get("name") or item.get("template-id") or "Nuclei detection"
            asset = (
                item.get("matched-at")
                or item.get("host")
                or item.get("url")
                or profile["url"]
            )
            template_id = item.get("template-id") or item.get("template") or "unknown"
            summary = f"Template {template_id} matched against {asset}"
            severity = self._severity_from_text(str(info.get("severity", "low")))
            description = info.get("description") or summary
            references = [str(ref) for ref in (info.get("reference") or []) if ref]
            classification = info.get("classification") or {}
            cwe = classification.get("cwe-id") if isinstance(classification, dict) else None

            findings.append(
                Finding(
                    id=stable_id("finding", f"nuclei:{template_id}:{title}:{asset}"),
                    source="nuclei",
                    category="scanner-match",
                    title=str(title),
                    description=str(description),
                    severity=severity,
                    asset=str(asset),
                    attack_surface=str(asset),
                    evidence=[
                        Evidence(source="nuclei", summary=summary, raw=item),
                    ],
                    references=references,
                    raw={**item, "cwe": cwe},
                )
            )
        return findings

    # -- nmap --------------------------------------------------------------

    def _from_nmap(self, profile: dict[str, str], scan_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        services = (scan_result.get("nmap") or {}).get("services", []) or []
        for service in services:
            try:
                port = int(service.get("port", 0))
            except (TypeError, ValueError):
                continue
            name = (service.get("service") or "unknown").strip()
            product = (service.get("product") or "").strip()
            version = (service.get("version") or "").strip()
            host = service.get("host") or profile["host"]

            severity = self.RISKY_PORTS.get(port, Severity.INFORMATIONAL)
            banner = " ".join(part for part in (name, product, version) if part).strip()
            summary = f"nmap reported {banner or 'a service'} open on port {port} of {host}."
            description = (
                f"Port {port} is reachable and exposes {banner or 'an unidentified service'}. "
                "Exposed administrative or data services increase the attack surface of the target."
            )
            if severity == Severity.INFORMATIONAL:
                description = (
                    f"Port {port} is open and running {banner or 'an unidentified service'}. "
                    "This is recorded for attack-surface inventory."
                )

            findings.append(
                Finding(
                    id=stable_id("finding", f"nmap:{host}:{port}:{name}"),
                    source="nmap",
                    category="service-exposure",
                    title=f"Open service {banner or 'unknown'} on {host}:{port}",
                    description=description,
                    severity=severity,
                    asset=f"{host}:{port}",
                    attack_surface=str(host),
                    evidence=[Evidence(source="nmap", summary=summary, raw=service)],
                    raw=service,
                )
            )
        return findings

    # -- ffuf --------------------------------------------------------------

    def _from_ffuf(self, profile: dict[str, str], fuzz_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for item in fuzz_result.get("ffuf", []) or []:
            url = item.get("url") or profile["url"]
            try:
                status = int(item.get("status", 0))
            except (TypeError, ValueError):
                status = 0
            fuzz_value = str((item.get("input") or {}).get("FUZZ", ""))
            lowered = fuzz_value.lower()
            if not any(hint in lowered for hint in self.SENSITIVE_HINTS):
                continue

            severity = Severity.MEDIUM if status in {200, 204} else Severity.LOW
            if status == 401 or status == 403:
                severity = Severity.INFORMATIONAL
            title = f"Potentially sensitive path exposed: {fuzz_value}"
            description = (
                f"ffuf discovered the candidate path or parameter `{fuzz_value}` on {url} "
                f"responding with status {status}."
            )
            if severity == Severity.INFORMATIONAL:
                description += (
                    " The resource requires authentication, so exposure is limited, but its "
                    "existence still reveals the application structure."
                )

            findings.append(
                Finding(
                    id=stable_id("finding", f"ffuf:{url}:{fuzz_value}:{status}"),
                    source="ffuf",
                    category=f"{item.get('mode', 'directory')}-exposure",
                    title=title,
                    description=description,
                    severity=severity,
                    asset=str(url),
                    attack_surface=str(url),
                    evidence=[
                        Evidence(
                            source="ffuf",
                            summary=(
                                f"mode={item.get('mode')} status={status} "
                                f"words={item.get('words')} lines={item.get('lines')} "
                                f"length={item.get('length')}"
                            ),
                            raw=item,
                        )
                    ],
                    raw=item,
                )
            )
        return findings

    # -- recon -------------------------------------------------------------

    def _from_recon(self, profile: dict[str, str], recon_result: dict[str, Any]) -> list[Finding]:
        """Record technology disclosure as an informational finding."""
        technologies = recon_result.get("technologies") or []
        if not technologies:
            return []
        summary = ", ".join(str(item) for item in technologies)
        asset = profile["url"]
        return [
            Finding(
                id=stable_id("finding", f"tech:{asset}:{summary}"),
                source="httpx",
                category="technology-disclosure",
                title=f"Technology fingerprint disclosed: {summary}",
                description=(
                    f"The target advertises the following technologies: {summary}. "
                    "Fingerprinted components let an attacker target known vulnerabilities "
                    "for those products."
                ),
                severity=Severity.INFORMATIONAL,
                asset=asset,
                attack_surface=asset,
                evidence=[
                    Evidence(
                        source="httpx",
                        summary=f"httpx tech-detect reported: {summary}",
                        raw={"technologies": technologies},
                    )
                ],
                raw={"technologies": technologies},
            )
        ]

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _severity_from_text(value: str) -> Severity:
        mapping = {
            "info": Severity.INFORMATIONAL,
            "informational": Severity.INFORMATIONAL,
            "unknown": Severity.INFORMATIONAL,
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(value.strip().lower(), Severity.LOW)
