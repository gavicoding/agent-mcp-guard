"""Command-line interface for agent-mcp-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

from . import __version__
from .discovery import candidate_locations, discover_system, display_path
from .i18n import t_rule, t_ui
from .lockfile import verify_lockfile, write_lockfile
from .models import Finding
from .reporters import render_report
from .rules import list_rules
from .scanner import discover_target_files, scan_manifest_text, scan_path, scan_text

SYSTEM_LOCK = Path.home() / ".agent-mcp-guard" / "system.lock.json"
LANGS = ["en", "pt"]


def _add_common(p: argparse.ArgumentParser, live_help: bool = True) -> None:
    p.add_argument("--lang", choices=LANGS, default="en")
    p.add_argument(
        "--system",
        action="store_true",
        help="Use the global configs of this machine (Claude, Cursor, VS Code, Windsurf, Codex, Gemini, ...) instead of a folder.",
    )
    if live_help:
        p.add_argument(
            "--live",
            action="store_true",
            help="Start/call each MCP server and check what it really advertises (runs the server's code).",
        )
        p.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for each live server (default 30).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-mcp-guard",
        description="Zero-dependency security scanner and SHA-256 rug-pull guard for AI agents and MCP configs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Audit a workspace, a config file or the whole machine (--system).")
    scan_p.add_argument("target", nargs="?", default=".", help="Workspace directory or single file to scan.")
    scan_p.add_argument("--format", choices=["terminal", "json", "sarif", "markdown", "html"], default="terminal")
    scan_p.add_argument("--output", "-o", help="Write report to a file instead of stdout.")
    scan_p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="high")
    scan_p.add_argument("--lockfile", help="Path to mcp-guard.lock.json for rug-pull verification.")
    scan_p.add_argument("--config", help="Path to .agent-mcp-guard.json.")
    scan_p.add_argument("--ignore-rule", action="append", default=[], help="Rule ID to ignore (repeatable).")
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output.")
    _add_common(scan_p)

    lock_p = sub.add_parser("lock", help="Pin MCP servers and tool schemas (SHA-256). With --live, pins what servers really advertise.")
    lock_p.add_argument("target", nargs="?", default=".", help="Workspace directory containing MCP manifests.")
    lock_p.add_argument("--out", help="Lockfile output path (default mcp-guard.lock.json, or ~/.agent-mcp-guard/system.lock.json with --system).")
    _add_common(lock_p)

    verify_p = sub.add_parser("verify", help="Check MCP configs (and, with --live, real tool descriptions) against the lockfile.")
    verify_p.add_argument("target", nargs="?", default=".", help="Workspace directory.")
    verify_p.add_argument("--lockfile", help="Lockfile to verify against.")
    _add_common(verify_p)

    where_p = sub.add_parser("where", help="List every config location checked by --system and which ones exist here.")
    where_p.add_argument("--lang", choices=LANGS, default="en")
    where_p.add_argument("--all", action="store_true", help="Also show locations that do not exist on this machine.")

    rules_p = sub.add_parser("rules", help="List all security rules with OWASP Agentic and CWE mappings.")
    rules_p.add_argument("--lang", choices=LANGS, default="en")

    demo_p = sub.add_parser("demo", help="Run a local self-test demo against the bundled vulnerable and hardened samples.")
    demo_p.add_argument("--lang", choices=LANGS, default="en")
    demo_p.add_argument("--no-color", action="store_true")
    return parser


def _target_files(args: argparse.Namespace) -> tuple[Path, list[Path], Callable[[Path], str]]:
    """(root, files, label) for a folder or for the whole machine."""
    if getattr(args, "system", False):
        home = Path.home()
        files = [loc.path for loc in discover_system()]
        return home, files, lambda p: display_path(p, home)
    target = Path(args.target).resolve()
    root = target if target.is_dir() else target.parent
    files = discover_target_files(target)

    def label(p: Path) -> str:
        try:
            return p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return p.as_posix()

    return root, files, label


def _live(files: list[Path], label: Callable[[Path], str], args: argparse.Namespace):
    from .livecheck import probe_all

    pt = args.lang == "pt"
    print(
        "Conferindo servidores MCP ao vivo (o código de cada servidor vai rodar neste computador)..."
        if pt
        else "Checking MCP servers live (each server's code will run on this machine)...",
        file=sys.stderr,
    )
    return probe_all(files, label, timeout=args.timeout, on_progress=lambda s: print(f"  - {s}", file=sys.stderr))


def _load_live_lock(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    live = data.get("live")
    return live if isinstance(live, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (ValueError, OSError):
            pass

    if args.command == "rules":
        for meta in list_rules():
            copy = t_rule(args.lang, meta.rule_id)
            print(f"{meta.rule_id} [{meta.severity.value.upper():8}] {copy['title']} ({meta.owasp_agentic} | {meta.cwe})")
        return 0

    if args.command == "where":
        existing = {str(loc.path).lower() for loc in discover_system()}
        for loc in candidate_locations():
            here = str(loc.path).lower() in existing
            if here or args.all:
                mark = "x" if here else " "
                print(f"[{mark}] {loc.client:28} {display_path(loc.path)}")
        found = discover_system()
        extra = [loc for loc in found if loc.kind == "instructions" and str(loc.path).lower() not in {str(c.path).lower() for c in candidate_locations()}]
        for loc in extra:
            print(f"[x] {loc.client:28} {display_path(loc.path)}")
        print(f"\n{len(found)} " + ("arquivo(s) encontrado(s)." if args.lang == "pt" else "file(s) found."))
        return 0

    if args.command in ("lock", "verify", "scan") and not args.system:
        target = Path(args.target).resolve()
        if not target.exists():
            print(f"Error: target not found: {target}", file=sys.stderr)
            return 2

    if args.command == "lock":
        root, files, label = _target_files(args)
        if args.out:
            out_path = Path(args.out)
        elif args.system:
            out_path = SYSTEM_LOCK
        else:
            out_path = root / "mcp-guard.lock.json"
        live_entries = None
        if args.live:
            from .livecheck import live_lock_entries

            probes = _live(files, label, args)
            live_entries = live_lock_entries(probes)
            for _f, name, res in probes:
                if not res.ok:
                    print(f"  ! {name}: {res.error}", file=sys.stderr)
        payload = write_lockfile(out_path, root, files, label=label, live=live_entries)
        extra = f", {len(payload['live'])} live" if "live" in payload else ""
        print(f"{t_ui(args.lang, 'lock_written')}: {out_path} ({len(payload['servers'])} servers, {len(payload['tools'])} tools{extra})")
        return 0

    if args.command == "verify":
        root, files, label = _target_files(args)
        lock_path = Path(args.lockfile) if args.lockfile else (SYSTEM_LOCK if args.system else root / "mcp-guard.lock.json")
        if not lock_path.is_absolute() and not args.system:
            lock_path = root / lock_path
        if not lock_path.is_file():
            print(f"Error: lockfile not found: {lock_path}", file=sys.stderr)
            return 2
        findings: list[Finding] = verify_lockfile(lock_path, root, files, label)
        if args.live:
            from .livecheck import live_findings

            probes = _live(files, label, args)
            live_all = live_findings(probes, _load_live_lock(lock_path) or {}, scan_text, scan_manifest_text)
            findings += [f for f in live_all if f.rule_id in ("AMG009", "AMG025")]
        if not findings:
            print(t_ui(args.lang, "lock_ok"))
            return 0
        print(t_ui(args.lang, "lock_drift"))
        for f in sorted(findings, key=lambda x: x.severity.rank):
            print(f"[{f.severity.value.upper()}] {f.rule_id} {f.file_path}: {f.evidence}")
        return 1 if any(f.rule_id == "AMG009" for f in findings) else 0

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
    root, files, label = _target_files(args)
    lock_path = Path(args.lockfile).resolve() if args.lockfile else (SYSTEM_LOCK if args.system and SYSTEM_LOCK.is_file() else None)
    cfg_path = Path(args.config).resolve() if args.config else None
    ignores = {r.strip().upper() for r in args.ignore_rule if r.strip()}
    extra: list[Finding] = []
    if args.live:
        from .livecheck import live_findings

        probes = _live(files, label, args)
        locked = _load_live_lock(lock_path or (root / "mcp-guard.lock.json"))
        extra = live_findings(probes, locked, scan_text, scan_manifest_text)
    report = scan_path(
        root if args.system else Path(args.target).resolve(),
        lockfile_path=lock_path,
        ignored_rules=ignores,
        config_path=cfg_path,
        files=files if args.system else None,
        label=label if args.system else None,
        require_lockfile=not args.system,
        extra_findings=extra,
    )
    rendered = render_report(report, args.format, lang=args.lang, no_color=args.no_color)

    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(rendered, encoding="utf-8")
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
