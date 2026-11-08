"""PoCEngine — non-destructive reproduction bundles.

Every generated proof of concept is read-only by construction: a replay of
the original request, a description of what to capture, and remediation
guidance. TRISHUL never emits an exploit, a payload or a destructive step.

The deterministic bundle is the published default. Content produced by the
model is *validated* first and may only **augment** that bundle -- it can
never replace it -- so a model that answers with a destructive step cannot
smuggle it into a report that claims to be non-destructive.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.engine.base import AgentContext, BaseAgent
from backend.app.models import Finding, PocBundle

POC_SYSTEM = """You are writing a bug-bounty proof of concept for an authorized security assessment.

Rules you must follow:
- Every step MUST be non-destructive. No data deletion, no modification, no exploitation, no credential attacks, no denial of service.
- Use only read-only requests (GET/HEAD) or a harmless, minimal validation request.
- Never include a working exploit payload, a shell command that changes state, or a brute-force loop.
- Be specific about what evidence to capture (status code, header, banner, response snippet).

Respond with a single JSON object and nothing else:
{
  "steps_to_reproduce": ["step 1", "step 2", "step 3"],
  "request_example": "a single safe read-only request or command",
  "response_example": "what the expected benign response looks like",
  "impact": "one or two sentences on real-world impact",
  "remediation": "one or two sentences of concrete remediation",
  "screenshot_guide": ["what to capture in screenshot 1", "..."],
  "video_script": ["scene 1", "..."]
}"""


#: Shell commands that change state. These are refused in *every* field the
#: model may contribute, including the narrative ones: a command that can
#: delete data or seize a service has no place in a proof of concept.
_DESTRUCTIVE_COMMANDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("rm", re.compile(r"(?i)\brm\s+-[a-z]*[rf][a-z]*\b")),
    ("mkfs", re.compile(r"(?i)\bmkfs(?:\.[a-z0-9]+)?\b")),
    ("dd", re.compile(r"(?i)\bdd\b[^\n]*\b(?:if|of)=")),
    (
        "service control",
        re.compile(
            r"(?i)(?:`|\$|>)\s*(?:sudo\s+)?(?:shutdown|reboot|halt|poweroff)\b"
            r"|\b(?:run|execute|exec)\s+(?:sudo\s+)?(?:shutdown|reboot|halt|poweroff)\b"
        ),
    ),
    ("systemctl", re.compile(r"(?i)\bsystemctl\s+(?:stop|disable|mask)\b")),
    ("pipe to shell", re.compile(r"(?i)\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b")),
    ("shell -c", re.compile(r"(?i)\b(?:ba|z|k)?sh\s+-c\b|\bcmd(?:\.exe)?\s+/c\b")),
    ("sql drop", re.compile(r"(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b")),
    ("sql delete", re.compile(r"(?i)\bdelete\s+from\b")),
    ("credential tool", re.compile(r"(?i)\b(?:hydra|sqlmap|medusa|ncrack|hashcat)\b")),
    ("metasploit", re.compile(r"(?i)\b(?:msfconsole|msfvenom|metasploit)\b")),
    ("fork bomb", re.compile(r":\s*\(\s*\)\s*\{[^}]*\}\s*;?\s*:")),
    ("package install", re.compile(r"(?i)\b(?:apt|apt-get|yum|dnf|pip|pip3|npm|brew)\s+install\b")),
    ("netcat shell", re.compile(r"(?i)\b(?:nc|ncat)\b[^\n]*\s-e\b")),
    (
        "system file write",
        re.compile(
            r"(?i)\btee\b[^\n]*\s(?:>|>>|-a)\s*/|\bdd\b[^\n]*\bof="
            r"|(?:^|\s)>>?\s*/(?:etc|bin|sbin|boot|usr|var|root|home)/"
        ),
    ),
    ("account change", re.compile(r"(?i)\b(?:useradd|usermod|adduser|passwd|chpasswd)\b")),
)

#: Wording that states an intent to destroy, attack or brute-force. This is
#: only checked in the instructional fields (the steps and the request
#: example): remediation advice legitimately says "remove the file".
_DESTRUCTIVE_INTENT = re.compile(
    r"(?i)\b(?:delete|remove|wipe|purge|erase|destroy|exploit|brute[- ]?force|credential[- ]?stuffing)\b"
)

#: Request shapes that change state on the target.
_UNSAFE_REQUESTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b"),
    re.compile(r"(?i)(?:^|\s)(?:--data(?:-raw|-binary|-urlencode)?|\bd\b)\s"),
    re.compile(r"(?i)\bmethod\s*[=:]\s*['\"]?(?:POST|PUT|PATCH|DELETE)\b"),
    re.compile(r"(?i)\b(?:POST|PUT|PATCH|DELETE)\s+/"),
)



class PoCEngine(BaseAgent):
    """Builds a reproduction bundle for every finding."""

    name = "PoCEngine"

    async def run(self, ctx: AgentContext, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            deterministic = self._deterministic_bundle(ctx, finding)
            augmented = await self._ai_augmented_bundle(ctx, finding, deterministic)
            finding.poc = augmented or deterministic
        return findings

    # -- deterministic -----------------------------------------------------

    def _deterministic_bundle(self, ctx: AgentContext, finding: Finding) -> PocBundle:
        asset = finding.asset
        host = asset.split(":")[0]
        is_port_finding = finding.source == "nmap" and ":" in asset and asset.rsplit(":", 1)[1].isdigit()

        if is_port_finding:
            port = asset.rsplit(":", 1)[1]
            request_example = f"nmap -Pn -p {port} -sV {host}"
            steps = [
                f"Confirm `{host}` is inside the approved scope of this engagement.",
                f"Run `{request_example}` to confirm the service is still reachable.",
                "Capture the reported service banner and version in a screenshot.",
                "Record whether the service needs to be reachable from the public internet.",
            ]
            impact = (
                "An exposed service enlarges the attack surface of the target and may expose "
                "an administrative or data interface to unauthenticated users."
            )
            remediation = (
                "Restrict the service to the networks that need it, bind it to an internal "
                "interface, and enforce authentication and access controls."
            )
        else:
            url = asset if asset.startswith(("http://", "https://")) else ctx.scan.target
            request_example = f"curl -isk --max-time 10 {url}"
            steps = [
                f"Confirm `{url}` is inside the approved scope of this engagement.",
                f"Replay `{request_example}` from a clean, authenticated-free session.",
                "Capture the response status line, the relevant headers and the minimal "
                "response snippet that proves the issue.",
                "Repeat the request once to confirm the behaviour is stable and not transient.",
            ]
            impact = (
                "The observed behaviour may expose sensitive functionality or a known "
                "weakness to unauthenticated users."
            )
            remediation = (
                "Patch or upgrade the affected component, restrict exposure to the required "
                "paths, and add server-side validation and access control as appropriate."
            )

        screenshot_guide = [
            "Capture the target URL or host together with the scope confirmation.",
            "Capture the exact, benign validation request that was sent.",
            "Capture the status code, response snippet or service banner proving the issue.",
        ]
        video_script = [
            "Open with the engagement reference and the scope confirmation.",
            "Show the exact non-destructive validation request.",
            "Pause on the response that proves the issue.",
            "Close with the impact and the recommended remediation.",
        ]

        bounty_report = self._bounty_report(finding, steps, impact, remediation)

        return PocBundle(
            steps_to_reproduce=steps,
            request_example=request_example,
            response_example=finding.evidence[0].summary if finding.evidence else "",
            impact=impact,
            remediation=remediation,
            screenshot_guide=screenshot_guide,
            video_script=video_script,
            bounty_report=bounty_report,
            generated_by="deterministic",
        )

    @staticmethod
    def _bounty_report(
        finding: Finding,
        steps: list[str],
        impact: str,
        remediation: str,
    ) -> str:
        """Render the published report from the steps that are actually shipped."""
        evidence_lines = [
            f"- {item.source}: {item.summary}" for item in finding.evidence[:8]
        ] or ["- (none recorded)"]

        return "\n".join(
            [
                f"## {finding.title}",
                f"- Severity: {finding.severity.value}",
                f"- Confidence: {finding.confidence}",
                f"- Verified: {'yes' if finding.verified else 'no'}",
                f"- Asset: {finding.asset}",
                "",
                "### Summary",
                finding.description,
                "",
                "### Steps to Reproduce",
                *[f"{index + 1}. {step}" for index, step in enumerate(steps)],
                "",
                "### Evidence",
                *evidence_lines,
                "",
                "### Impact",
                impact,
                "",
                "### Remediation",
                remediation,
            ]
        )

    # -- AI ----------------------------------------------------------------

    @staticmethod
    def _reject_reason(text: str, *, instructional: bool) -> str | None:
        """Return why ``text`` is unsafe, or ``None`` when it is acceptable.

        ``instructional`` marks the fields that tell the operator what to do
        (the steps and the request example). Those are held to a stricter
        standard: a destructive *intent* is refused there, while the
        narrative fields are only checked for destructive *commands*, so
        ordinary remediation advice stays usable.
        """
        for label, pattern in _DESTRUCTIVE_COMMANDS:
            if pattern.search(text):
                return f"a destructive command ({label})"
        if instructional:
            if _DESTRUCTIVE_INTENT.search(text):
                return "a destructive intent"
            for pattern in _UNSAFE_REQUESTS:
                if pattern.search(text):
                    return "a request that changes state"
        return None

    def _validate_payload(self, payload: dict[str, Any]) -> str | None:
        """Validate every field the model may contribute.

        A single unsafe field rejects the whole bundle: the deterministic
        bundle is always a safe fallback, so there is no reason to publish a
        partially validated proof of concept.
        """
        steps = [str(item) for item in payload.get("steps_to_reproduce") or [] if str(item).strip()]
        for index, step in enumerate(steps, start=1):
            reason = self._reject_reason(step, instructional=True)
            if reason:
                return f"step {index} contains {reason}"

        request_example = str(payload.get("request_example") or "")
        if request_example:
            reason = self._reject_reason(request_example, instructional=True)
            if reason:
                return f"the request example contains {reason}"

        narrative = (
            ("response_example", payload.get("response_example")),
            ("impact", payload.get("impact")),
            ("remediation", payload.get("remediation")),
        )
        for label, value in narrative:
            text = str(value or "")
            if not text:
                continue
            reason = self._reject_reason(text, instructional=False)
            if reason:
                return f"the {label} contains {reason}"

        for label in ("screenshot_guide", "video_script"):
            for index, item in enumerate(payload.get(label) or [], start=1):
                text = str(item)
                if not text.strip():
                    continue
                reason = self._reject_reason(text, instructional=False)
                if reason:
                    return f"{label} entry {index} contains {reason}"
        return None

    async def _ai_augmented_bundle(
        self,
        ctx: AgentContext,
        finding: Finding,
        deterministic: PocBundle,
    ) -> PocBundle | None:
        """Ask the model for extra content and merge it in -- safely.

        The deterministic bundle stays the backbone. Validated model content
        is appended to it and used for the narrative fields; anything unsafe
        is discarded and the deterministic bundle is published unchanged.
        """
        prompt = (
            f"Finding:\n{self.finding_summary(finding)}\n\n"
            f"Current severity: {finding.severity.value}\n"
            f"Current confidence: {finding.confidence}\n"
        )
        payload = await self.ai_json(ctx, POC_SYSTEM, prompt, max_tokens=1200)
        if not payload:
            return None

        steps = [
            str(item) for item in payload.get("steps_to_reproduce") or [] if str(item).strip()
        ]
        if not steps:
            return None

        reason = self._validate_payload(payload)
        if reason:
            ctx.ai_errors.append(
                f"{self.name}: rejected the AI proof of concept for {finding.id}: {reason}."
            )
            return None

        # The deterministic steps come first; the validated model steps are
        # appended so the published bundle never loses its safe backbone.
        merged_steps = list(deterministic.steps_to_reproduce)
        for step in steps:
            if step not in merged_steps:
                merged_steps.append(step)

        impact = str(payload.get("impact") or deterministic.impact)
        remediation = str(payload.get("remediation") or deterministic.remediation)
        request_example = str(payload.get("request_example") or deterministic.request_example)
        response_example = str(payload.get("response_example") or deterministic.response_example)
        screenshot_guide = [
            str(item) for item in payload.get("screenshot_guide") or []
        ] or deterministic.screenshot_guide
        video_script = [
            str(item) for item in payload.get("video_script") or []
        ] or deterministic.video_script

        return PocBundle(
            steps_to_reproduce=merged_steps,
            request_example=request_example,
            response_example=response_example,
            impact=impact,
            remediation=remediation,
            screenshot_guide=screenshot_guide,
            video_script=video_script,
            # The report is rebuilt from what is actually published, so it
            # lists the merged steps rather than the deterministic ones.
            bounty_report=self._bounty_report(
                finding, merged_steps, impact, remediation
            ),
            generated_by="ai",
        )
