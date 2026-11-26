"""Command-line interface for agent-mcp-guard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .i18n import t_rule, t_ui
from .lockfile import verify_lockfile, write_lockfile
from .reporters import render_report
from .rules import list_rules
from .scanner import discover_target_files, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-mcp-guard",
        description="Zero-dependency security scanner and SHA-256 rug-pull guard for AI agents and MCP configs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Audit a workspace or config file for agent and MCP risks.")
    scan_p.add_argument("target", nargs="?", default=".", help="Workspace directory or single file to scan.")
    scan_p.add_argument("--format", choices=["terminal", "json", "sarif", "markdown", "html"], default="terminal")
    scan_p.add_argument("--output", "-o", help="Write report to a file instead of stdout.")
    scan_p.add_argument("--lang", choices=["en", "pt"], default="en")
    scan_p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="high")
    scan_p.add_argument("--lockfile", help="Path to mcp-guard.lock.json for rug-pull verification.")
    scan_p.add_argument("--config", help="Path to .agent-mcp-guard.json.")
    scan_p.add_argument("--ignore-rule", action="append", default=[], help="Rule ID to ignore (repeatable).")
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output.")

    lock_p = sub.add_parser("lock", help="Create a SHA-256 baseline lockfile for MCP servers and tool schemas.")
    lock_p.add_argument("target", nargs="?", default=".", help="Workspace directory containing MCP manifests.")
    lock_p.add_argument("--out", default="mcp-guard.lock.json", help="Lockfile output path.")
    lock_p.add_argument("--lang", choices=["en", "pt"], default="en")

    verify_p = sub.add_parser("verify", help="Verify current MCP configs and tool schemas against mcp-guard.lock.json.")
    verify_p.add_argument("target", nargs="?", default=".", help="Workspace directory.")
    verify_p.add_argument("--lockfile", default="mcp-guard.lock.json", help="Lockfile to verify against.")
    verify_p.add_argument("--lang", choices=["en", "pt"], default="en")

    rules_p = sub.add_parser("rules", help="List all 20 security rules with OWASP Agentic and CWE mappings.")
    rules_p.add_argument("--lang", choices=["en", "pt"], default="en")

    demo_p = sub.add_parser("demo", help="Run a local self-test demo against the bundled vulnerable and hardened samples.")
    demo_p.add_argument("--lang", choices=["en", "pt"], default="en")
    demo_p.add_argument("--no-color", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        for meta in list_rules():
            copy = t_rule(args.lang, meta.rule_id)
            print(f"{meta.rule_id} [{meta.severity.value.upper():8}] {copy['title']} ({meta.owasp_agentic} | {meta.cwe})")
        return 0

    if args.command == "lock":
        target = Path(args.target).resolve()
        if not target.exists():
            print(f"Error: target not found: {target}", file=sys.stderr)
            return 2
        files = discover_target_files(target)
        out_path = Path(args.out)
        if not out_path.is_absolute() and target.is_dir():
            out_path = target / out_path
        payload = write_lockfile(out_path, target, files)
        print(
            f"{t_ui(args.lang, 'lock_written')}: {out_path} "
            f"({len(payload['servers'])} servers, {len(payload['tools'])} tools)"
        )
        return 0

    if args.command == "verify":
        target = Path(args.target).resolve()
        lock_path = Path(args.lockfile)
        if not lock_path.is_absolute() and target.is_dir():
            lock_path = target / lock_path
        if not lock_path.is_file():
            print(f"Error: lockfile not found: {lock_path}", file=sys.stderr)
            return 2
        files = discover_target_files(target)
        findings = verify_lockfile(lock_path, target, files)
        if not findings:
            print(t_ui(args.lang, "lock_ok"))
            return 0
        print(t_ui(args.lang, "lock_drift"))
        for f in findings:
            print(f"[CRITICAL] {f.rule_id} {f.file_path}: {f.evidence}")
        return 1

    if args.command == "demo":
        repo_root = _find_samples_root()
        if repo_root is None:
            print("Error: bundled samples/ directory not found.", file=sys.stderr)
            return 2
        vuln = repo_root / "vulnerable-workspace"
        clean = repo_root / "hardened-workspace"
        r1 = scan_path(vuln, lockfile_path=vuln / "mcp-guard.lock.json")
        r2 = scan_path(clean, lockfile_path=clean / "mcp-guard.lock.json")
        print("=== VULNERABLE WORKSPACE ===")
        print(render_report(r1, "terminal", lang=args.lang, no_color=args.no_color))
        print("\n=== HARDENED WORKSPACE ===")
        print(render_report(r2, "terminal", lang=args.lang, no_color=args.no_color))
        return 0

    # scan
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target not found: {target}", file=sys.stderr)
        return 2
    lock_path = Path(args.lockfile).resolve() if args.lockfile else None
    cfg_path = Path(args.config).resolve() if args.config else None
    ignores = {r.strip().upper() for r in args.ignore_rule if r.strip()}
    report = scan_path(target, lockfile_path=lock_path, ignored_rules=ignores, config_path=cfg_path)
    rendered = render_report(report, args.format, lang=args.lang, no_color=args.no_color)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 1 if report.exceeds_threshold(args.fail_on) else 0


def _find_samples_root() -> Path | None:
    candidates = [
        Path.cwd() / "samples",
        Path(__file__).resolve().parents[2] / "samples",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None
