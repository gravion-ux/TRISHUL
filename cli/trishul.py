#!/usr/bin/env python3
"""TRISHUL command line interface.

Usage:
    trishul example.com --mode deep
    trishul --health
    trishul --provider
    trishul --autofix

The CLI enforces the same authorisation gate as the API: a scan only starts
after the operator explicitly confirms that they are authorised to test the
target.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.events import event_bus  # noqa: E402
from backend.app.core.utils import redact  # noqa: E402
from backend.app.main import (  # noqa: E402
    ai_manager,
    health_service,
    master_agent,
    storage,
    tool_registry,
)
from backend.app.models import GuideAction, ScanMode, ScanRequest  # noqa: E402

BANNER = "\n".join(
    [
        "",
        "███████████  ███████ ███    ██  ███████ ██   ██ ██    ██ ███████ ",
        "██    ██ ██      ███    ██ ██       ███    ██ ██   ██ ██    ██ ",
        "███████████     ███    █████       ███    ██ ██   ██ ██    ██ ",
        "██    ██ ██      ███    ██ ██       ███    ██  ██  ██  ██    ██ ",
        "██    ██  ███████ ███    ██  ███████ ███    ██   ██   ███████ ",
        "",
        "  Authorized security testing platform — Local and Provider editions",
        "",
    ]
)

SAFETY_NOTICE = (
    "  ⚠  AUTHORIZED SECURITY TESTING ONLY\n"
    '  "Hey kid, don\'t ride a horse that isn\'t yours"\n'
)


def render_progress(percent: int, width: int = 30) -> str:
    filled = int((percent / 100) * width)
    return "[" + ("#" * filled).ljust(width, "-") + f"] {percent:3d}%"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def stream_events(scan_id: str) -> None:
    """Print progress events for a scan until it finishes."""
    queue = event_bus.subscribe(scan_id)
    try:
        while True:
            event = await queue.get()
            if event.get("type") != "progress":
                continue
            percent = int(event.get("percent", 0))
            stage = event.get("stage", "")
            message = event.get("message", "")
            print(f"{render_progress(percent)} {stage:<10} {redact(message)}")
            if stage in {"completed", "failed", "cancelled"}:
                break
    finally:
        event_bus.unsubscribe(scan_id, queue)


async def run_scan(args: argparse.Namespace) -> int:
    """Run a scan from the command line."""
    print(BANNER)
    print(SAFETY_NOTICE)

    health = await health_service.get_health_async()
    missing = [tool for tool in health.tools if tool.required and not tool.installed]
    if missing:
        print("Missing required tools:")
        for tool in missing:
            print(f"  - {tool.name}: {tool.fix_command}")
        print()
        print("Run `./install.sh` on Kali Linux, or `trishul --autofix` for the command list.")
        return 1

    config = ai_manager.current_config()
    print(f"  AI provider : {config.provider.value} ({config.model}) @ {config.base_url}")
    print(f"  Edition     : {config.edition.value}")
    if not health.ai.reachable:
        print(f"  AI status   : {health.ai.message}")
        print("               The scan will still run; AI stages fall back to deterministic results.")
    print()

    if not args.yes:
        confirmation = input(
            "Type YES to confirm you are authorised to scan this target: "
        ).strip()
        if confirmation != "YES":
            print("Authorization confirmation not provided. Exiting.")
            return 1

    note = args.auth_note or input(
        "Authorization note (ticket / program / scope reference): "
    ).strip()
    if len(note) < 5:
        print("Authorization note must be at least 5 characters.")
        return 1

    request = ScanRequest(
        target=args.target,
        mode=ScanMode(args.mode),
        authorized=True,
        authorization_note=note,
        thread_limit=args.threads,
        timeout_seconds=args.timeout,
    )

    scan = master_agent.create_scan(request)
    event_task = asyncio.create_task(stream_events(scan.id))
    await master_agent.run_scan(scan.id)
    try:
        await asyncio.wait_for(event_task, timeout=5)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        event_task.cancel()

    completed = storage.get_scan(scan.id)
    if not completed:
        print("Scan record missing after completion.")
        return 1

    print()
    print(f"Scan status   : {completed.status.value}")
    print(f"Findings      : {len(completed.findings)}")
    if completed.ai_provider:
        print(f"AI provider   : {completed.ai_provider} ({completed.ai_model})")
    if completed.report_paths:
        print("Reports       :")
        for name, path in completed.report_paths.items():
            print(f"  - {name}: {path}")
    if completed.error:
        print(f"Error         : {completed.error}")
        return 1

    if not completed.findings:
        print()
        print("No findings were produced. The target may be unreachable or not exposed.")
        return 0

    print()
    print_findings(completed)

    if not args.interactive:
        return 0

    print()
    print("What would you like to do?")
    print("1. Guide me step-by-step (manual PoC)")
    print("2. Show report paths only")
    print("3. Skip")
    choice = input("> ").strip()
    if choice == "1":
        await handle_guide(completed.id)
    return 0


async def handle_guide(scan_id: str) -> None:
    """Walk the operator through the manual validation steps."""
    scan = storage.get_scan(scan_id)
    if not scan or not scan.findings:
        print("No findings available.")
        return
    print()
    print("Choose a finding:")
    for index, finding in enumerate(scan.findings, start=1):
        print(
            f"  {index}. [{finding.severity.value}] {finding.title} "
            f"(confidence {finding.confidence})"
        )
    try:
        selected = int(input("> ").strip()) - 1
    except ValueError:
        print("Invalid selection.")
        return
    if selected < 0 or selected >= len(scan.findings):
        print("Selection out of range.")
        return

    guide = await master_agent.start_guide(scan_id, scan.findings[selected].id)
    while True:
        current = storage.get_guide(guide.id)
        if not current or current.status == "completed":
            print("Guide completed.")
            break
        if not current.steps:
            break
        step = current.steps[min(current.current_step, len(current.steps) - 1)]
        print()
        print(f"Step {step.index + 1}/{len(current.steps)}")
        print(f"  {step.instruction}")
        action = input("Action [next/done/hint/retry]: ").strip().lower()
        if action not in {"next", "done", "hint", "retry"}:
            print("Invalid action.")
            continue
        updated = await master_agent.advance_guide(guide.id, GuideAction(action))
        if action == "hint":
            active = updated.steps[min(updated.current_step, len(updated.steps) - 1)]
            print(f"Hint: {active.hint}")


def print_findings(scan) -> None:
    """Print a compact summary of every finding."""
    for finding in scan.findings:
        print("-" * 74)
        print(f"[{finding.severity.value}] {finding.title}")
        print(f"  Asset      : {finding.asset}")
        print(
            f"  Confidence : {finding.confidence} "
            f"(evidence baseline {finding.baseline_confidence})"
            f" | verified: {finding.verified}"
        )
        if finding.ai_adjusted:
            print("  AI         : adjudicated this finding")
        print(f"  {finding.description}")
        if finding.poc:
            print(f"  Request    : {finding.poc.request_example}")
            print(f"  Impact     : {finding.poc.impact}")
            print(f"  Fix        : {finding.poc.remediation}")


def run_health() -> int:
    """Print the health report."""
    print(BANNER)
    health = asyncio.run(health_service.get_health_async())
    print(f"  Version    : {health.version}")
    print(f"  Edition    : {health.edition.value}")
    print(f"  Platform   : {health.platform}")
    print(f"  Ready      : {'yes' if health.ready else 'no'}")
    print()
    print("  Tools:")
    for tool in health.tools:
        marker = "✓" if tool.installed else "✗"
        required = " (required)" if tool.required else ""
        version = f" — {tool.version}" if tool.version else ""
        print(f"    {marker} {tool.name}{required}{version}")
    print()
    print(f"  AI         : {health.ai.provider} / {health.ai.model}")
    print(f"  AI status  : {health.ai.message}")
    if health.autofix_commands:
        print()
        print("  Suggested remediation commands (not executed):")
        for command in health.autofix_commands:
            print(f"    $ {command}")
    return 0 if health.ready else 1


def run_provider(args: argparse.Namespace) -> int:
    """Show or change the active AI provider configuration."""
    if args.provider_set:
        from backend.app.models import ProviderConfigRequest, ProviderKind

        try:
            kind = ProviderKind(args.provider_set)
        except ValueError:
            print(f"Unknown provider: {args.provider_set}")
            print("Valid providers: " + ", ".join(item.value for item in ProviderKind))
            return 1
        request = ProviderConfigRequest(
            provider=kind,
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            edition=args.edition,
        )
        config = ai_manager.save_config(request)
        print(f"Provider saved: {config.provider.value} / {config.model} @ {config.base_url}")
        if config.has_api_key:
            print(f"API key stored (hint: {config.api_key_hint})")
        return 0

    config = ai_manager.current_config()
    print(BANNER)
    print(f"  Edition    : {config.edition.value}")
    print(f"  Provider   : {config.provider.value}")
    print(f"  Model      : {config.model}")
    print(f"  Base URL   : {config.base_url}")
    print(f"  API key    : {'configured (' + config.api_key_hint + ')' if config.has_api_key else 'not configured'}")
    print()
    print("  Available providers:")
    for descriptor in ai_manager.catalog():
        print(
            f"    {descriptor.kind.value:<18} {descriptor.edition.value:<9} "
            f"{descriptor.default_base_url}  — {descriptor.notes}"
        )
    return 0


def run_autofix() -> int:
    """Show — and optionally run — the commands that install missing tools.

    Commands are executed without a shell: the command string is split with
    ``shlex.split`` and passed to ``subprocess.run`` as an argv list.
    """
    commands = tool_registry.autofix_commands()
    if not commands:
        print("No missing tools detected. Nothing to do.")
        return 0
    print(BANNER)
    print("Autofix commands:")
    for command in commands:
        print(f"  $ {command}")
    print()
    confirm = input("Run these commands now? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Nothing was executed.")
        return 1

    env = os.environ.copy()
    env["PATH"] = f"{env.get('PATH', '')}{os.pathsep}{Path.home() / 'go' / 'bin'}"
    for command in commands:
        argv = shlex.split(command)
        if not argv:
            continue
        print(f"  $ {command}")
        try:
            completed = subprocess.run(argv, env=env, cwd=str(ROOT_DIR), check=False, shell=False)
        except OSError as exc:
            print(f"Command failed to start: {exc}")
            return 1
        if completed.returncode != 0:
            print(f"Command failed with exit code {completed.returncode}")
            return completed.returncode
    print()
    print("Autofix completed. Re-run `trishul --health` to verify.")
    return 0


def run_update() -> int:
    """Refresh nuclei templates and the optional wordlist repository."""
    from backend.app.main import updater_service

    print(BANNER)
    print("Updating nuclei templates and payload lists...")
    details = asyncio.run(updater_service.update_all())
    print(json.dumps(redact(details), indent=2))
    return 0 if all(item.get("success") for item in details.values()) else 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trishul",
        description="TRISHUL — authorized-scope AI-powered security testing platform.",
    )
    parser.add_argument("target", nargs="?", help="Target host or URL to assess.")
    parser.add_argument("--mode", default="deep", choices=["quick", "deep"], help="Scan depth.")
    parser.add_argument("--threads", type=int, default=8, help="Tool thread limit (1-32).")
    parser.add_argument("--timeout", type=int, default=900, help="Per-tool timeout in seconds.")
    parser.add_argument(
        "--yes", action="store_true", help="Skip the interactive authorisation prompt."
    )
    parser.add_argument("--auth-note", default="", help="Authorisation note, ticket or scope reference.")
    parser.add_argument(
        "--no-interactive", dest="interactive", action="store_false",
        help="Do not prompt for post-scan actions.",
    )
    parser.set_defaults(interactive=True)
    parser.add_argument("--health", action="store_true", help="Print the health report and exit.")
    parser.add_argument("--autofix", action="store_true", help="Show and optionally run dependency install commands.")
    parser.add_argument("--provider", action="store_true", help="Show the AI provider configuration.")
    parser.add_argument("--provider-set", default="", metavar="PROVIDER", help="Switch the AI provider.")
    parser.add_argument("--model", default="", help="Model id used with --provider-set.")
    parser.add_argument("--base-url", default="", help="Base URL used with --provider-set.")
    parser.add_argument("--api-key", default="", help="API key used with --provider-set (stored encrypted).")
    parser.add_argument("--edition", default="", choices=["", "local", "provider"], help="Edition used with --provider-set.")
    parser.add_argument("--update", action="store_true", help="Refresh nuclei templates and wordlists.")
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"TRISHUL {get_settings().app.version}")
        return

    if args.health:
        raise SystemExit(run_health())
    if args.autofix:
        raise SystemExit(run_autofix())
    if args.provider or args.provider_set:
        raise SystemExit(run_provider(args))
    if args.update:
        raise SystemExit(run_update())
    if not args.target:
        parser.error("target is required (or use --health / --provider / --autofix)")

    try:
        raise SystemExit(asyncio.run(run_scan(args)))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
