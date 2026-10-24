#!/usr/bin/env python3
"""
Veriflow Security Verification Runner (Phase 5).

One entry point for both halves of Veriflow's security phase:

- **Static scan** (default, always safe): read-only pattern and configuration
  inspection of the project tree. Executes no project code, opens no socket.
- **Live checks** (``--url``, requires ``--execute``): runtime verification of
  headers, cookie flags, output encoding, access control, cross-user isolation,
  error disclosure, redirects and CSRF against a loopback service.

Preview is the default for the live half: without ``--execute`` the runner
prints the checks it *would* send and sends nothing. The static scan is
read-only by construction and so runs without an opt-in.

Exit codes:
    0  no CRITICAL or HIGH static finding and no live FAIL.
    1  at least one CRITICAL/HIGH static finding, or a live check failed.
    2  usage error, unsafe target, or an unknown filter.

Windows PowerShell examples:
    python skills\\veriflow\\scripts\\run-security-tests.py .
    python skills\\veriflow\\scripts\\run-security-tests.py . --json
    python skills\\veriflow\\scripts\\run-security-tests.py . --category secrets
    python skills\\veriflow\\scripts\\run-security-tests.py --url http://127.0.0.1:8099
    python skills\\veriflow\\scripts\\run-security-tests.py --url http://127.0.0.1:8099 --execute
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

try:  # noqa: E402  - sys.path is prepared above
    from skills.veriflow.scripts.api_safety import UnsafeTargetError
    from skills.veriflow.scripts.security_checks import (
        LIVE_CHECKS_BY_ID,
        SecurityTarget,
        preview_live_checks,
        run_live_security_checks,
    )
    from skills.veriflow.scripts.security_scanner import (
        SCANNER_CATEGORIES,
        format_scan_report,
        scan_project,
    )
except ImportError:  # pragma: no cover - direct execution outside the repo
    from api_safety import UnsafeTargetError
    from security_checks import (
        LIVE_CHECKS_BY_ID,
        SecurityTarget,
        preview_live_checks,
        run_live_security_checks,
    )
    from security_scanner import (
        SCANNER_CATEGORIES,
        format_scan_report,
        scan_project,
    )


def _load_changed_files():
    """Load the shared changed-files helper, or None when unavailable.

    Imported lazily and defensively: --changed is an optimisation, and a
    missing helper must widen the scan rather than fail the run.
    """
    try:
        from skills.veriflow.scripts import changed_files as mod  # type: ignore
        return mod
    except ImportError:
        pass
    try:
        import changed_files as mod  # type: ignore
        return mod
    except ImportError:
        return None


def _build_target(args: argparse.Namespace) -> SecurityTarget:
    """Translate CLI arguments into a validated live-check target."""
    user_a: Optional[Dict[str, str]] = None
    user_b: Optional[Dict[str, str]] = None
    if args.user_a_token and args.user_b_resource:
        user_a = {"token": args.user_a_token}
        user_b = {"resource_path": args.user_b_resource}

    return SecurityTarget(
        base_url=args.url,
        public_path=args.public_path,
        protected_path=args.protected_path,
        reflect_path=args.reflect_path,
        reflect_param=args.reflect_param,
        error_path=args.error_path,
        login_path=args.login_path,
        login_payload={"username": "vf-fixture-user", "password": "vf-fixture-password"},
        user_a=user_a,
        user_b=user_b,
        state_change_path=args.state_change_path,
        redirect_path=args.redirect_path,
        redirect_param=args.redirect_param,
        allow_external=args.allow_external,
        timeout=args.timeout,
    )


def _format_live_preview(target: SecurityTarget, planned: List[Dict[str, Any]]) -> str:
    """Render the live-check preview. No request has been sent at this point."""
    lines = [
        "=" * 60,
        "Veriflow -- Live Security Check Preview",
        "=" * 60,
        f"Target:          {target.base_url}",
        f"External target: {'authorized' if target.allow_external else 'blocked (loopback only)'}",
        f"Timeout:         {target.timeout}s",
        "-" * 60,
    ]
    for item in planned:
        lines.append(f"  [{item['status']}] {item['test_id']}: {item['name']}")
        lines.append(f"      Catalog: {', '.join(item['catalog_ids']) or 'n/a'}")
        lines.append(f"      Reason:  {item['reason']}")
    lines.extend(
        [
            "-" * 60,
            "Safety Notice:",
            "  Preview only. No HTTP request has been sent to the target.",
            "  Pass --execute to run these checks.",
            "=" * 60,
        ]
    )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run-security-tests.py",
        description="Veriflow security verification: static scan and opt-in live checks.",
        epilog=(
            "The static scan is read-only. Live checks require --url and --execute, and "
            "target loopback addresses unless --allow-external is given."
        ),
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Project directory for the static scan (default: current directory).",
    )
    parser.add_argument("--json", action="store_true", help="Emit a structured JSON report.")

    static_group = parser.add_argument_group("static scan")
    static_group.add_argument(
        "--no-static", action="store_true", help="Skip the static scan (live checks only)."
    )
    static_group.add_argument(
        "--category",
        action="append",
        dest="categories",
        help=f"Restrict the scan to a category (repeatable). Available: {', '.join(SCANNER_CATEGORIES)}",
    )
    static_group.add_argument(
        "--rule",
        action="append",
        dest="rule_ids",
        help="Restrict the scan to a rule id (repeatable).",
    )
    static_group.add_argument(
        "--exclude",
        action="append",
        dest="exclude_paths",
        help=(
            "Path glob to exclude from the scan, relative to the scan root (repeatable). "
            "Exclusions are disclosed in the report, never silent."
        ),
    )
    static_group.add_argument(
        "--no-ignore-file",
        action="store_true",
        help="Ignore the project's .veriflow-security-ignore file.",
    )
    static_group.add_argument(
        "--changed",
        nargs="?",
        const="",
        default=None,
        metavar="BASE",
        help=(
            "Limit the scan to files changed according to git. With BASE, compares "
            "against that revision; without it, uses staged, unstaged and untracked "
            "changes. Falls back to a full scan, with the reason stated in the report, "
            "when git cannot answer."
        ),
    )

    live_group = parser.add_argument_group("live checks")
    live_group.add_argument("--url", help="Base URL of a running service, e.g. http://127.0.0.1:8099")
    live_group.add_argument(
        "--execute",
        action="store_true",
        help="Actually send the live check requests. Without it, live checks are previewed only.",
    )
    live_group.add_argument(
        "--check",
        action="append",
        dest="check_filter",
        help="Restrict live checks to a check id (repeatable).",
    )
    live_group.add_argument(
        "--allow-external",
        action="store_true",
        help="Authorize a non-loopback target. Only use this against a system you own and are permitted to test.",
    )
    live_group.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5.0).")
    live_group.add_argument("--public-path", default="/", help="Unauthenticated path (default: /).")
    live_group.add_argument("--protected-path", help="Path that must refuse an anonymous request.")
    live_group.add_argument("--reflect-path", help="Path that echoes a query parameter into its response.")
    live_group.add_argument("--reflect-param", default="q", help="Query parameter the reflect path echoes (default: q).")
    live_group.add_argument("--error-path", help="Path that deliberately fails, to inspect error handling.")
    live_group.add_argument("--login-path", help="Path that issues a session cookie.")
    live_group.add_argument("--state-change-path", help="Path whose POST changes state, for the CSRF check.")
    live_group.add_argument("--redirect-path", help="Path that accepts a redirect destination parameter.")
    live_group.add_argument("--redirect-param", default="next", help="Redirect destination parameter (default: next).")
    live_group.add_argument("--user-a-token", help="Synthetic token for user A (cross-user isolation check).")
    live_group.add_argument("--user-b-resource", help="Path to user B's resource (cross-user isolation check).")

    args = parser.parse_args(argv)

    if args.no_static and not args.url:
        parser.error("--no-static leaves nothing to do: pass --url to run live checks.")

    if args.check_filter and not args.url:
        parser.error("--check applies to live checks and requires --url.")

    payload: Dict[str, Any] = {"engine": "veriflow-security", "static": None, "live": None}
    exit_code = 0

    # ---------------- static scan ---------------- #
    if not args.no_static:
        include_paths = None
        change_info = None
        if args.changed is not None:
            change_mod = _load_changed_files()
            if change_mod is None:
                change_info = {
                    "narrowed": False,
                    "fallback_reason": "the changed-files helper could not be loaded",
                }
            else:
                change_set = change_mod.resolve_changed_files(
                    args.root, args.changed or None, source_only=False
                )
                change_info = change_set.to_dict()
                if change_set.narrowed and change_set.files:
                    include_paths = change_set.files
                elif change_set.narrowed:
                    # Narrowing succeeded but matched nothing. Scanning zero
                    # files would print a clean report, so widen instead.
                    change_info["fallback_reason"] = (
                        "no changed files were found, so the full tree was scanned "
                        "rather than reporting a clean scan over nothing"
                    )
                    change_info["narrowed"] = False

        try:
            report = scan_project(
                args.root,
                categories=args.categories,
                rule_ids=args.rule_ids,
                exclude_paths=args.exclude_paths,
                use_ignore_file=not args.no_ignore_file,
                include_paths=include_paths,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

        if change_info is not None and not change_info.get("narrowed"):
            report.limitations.append(
                f"--changed could not narrow the scan ({change_info.get('fallback_reason')}); "
                "the full tree was scanned instead."
            )
        elif change_info is not None:
            report.limitations.append(
                f"--changed restricted this scan to {len(include_paths or [])} changed "
                "file(s). Unchanged files were not inspected, so this is a narrowed scan, "
                "not a clean bill of health for the project."
            )

        payload["static"] = report.to_dict()
        if change_info is not None:
            payload["changed_scope"] = change_info
        if not args.json:
            print(format_scan_report(report))

        counts = report.severity_counts()
        if counts["CRITICAL"] or counts["HIGH"]:
            exit_code = 1

    # ---------------- live checks ---------------- #
    if args.url:
        target = _build_target(args)

        if not args.execute:
            planned = preview_live_checks(target)
            payload["live"] = {
                "mode": "preview",
                "target_url": target.base_url,
                "planned_checks": planned,
                "safety_notice": "Preview only. No HTTP request was sent.",
            }
            if not args.json:
                print()
                print(_format_live_preview(target, planned))
        else:
            if args.check_filter:
                unknown = sorted(set(args.check_filter) - set(LIVE_CHECKS_BY_ID))
                if unknown:
                    print(
                        f"Error: unknown live check id(s): {', '.join(unknown)}. "
                        f"Available: {', '.join(sorted(LIVE_CHECKS_BY_ID))}",
                        file=sys.stderr,
                    )
                    return 2
            try:
                live_report = run_live_security_checks(target, check_filter=args.check_filter)
            except UnsafeTargetError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2

            payload["live"] = {"mode": "executed", **live_report.to_dict()}
            if not args.json:
                print()
                print(live_report.format_text())

            if live_report.summary_counts()["FAIL"]:
                exit_code = 1

    if args.json:
        print(json.dumps(payload, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
