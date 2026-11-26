"""Turn live MCP probe results into findings and lockfile entries."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .configload import load_config_text
from .live import LiveResult, probe_server
from .lockfile import extract_servers, is_mcp_config_path
from .models import Finding, Severity
from .rules import RULES


def _f(rule_id: str, where: str, evidence: str, severity: Severity | None = None) -> Finding:
    return Finding(rule_id=rule_id, severity=severity or RULES[rule_id].severity, file_path=where, line=1, column=1, evidence=evidence)


def probe_all(
    files: list[Path],
    label: Callable[[Path], str],
    timeout: float = 30.0,
    on_progress: Callable[[str], None] | None = None,
) -> list[tuple[str, str, LiveResult]]:
    """Probe every server declared in the given config files. Returns (file_label, server, result)."""
    out: list[tuple[str, str, LiveResult]] = []
    for path in files:
        if not is_mcp_config_path(path):
            continue
        try:
            data = load_config_text(path, path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for name, cfg in extract_servers(data).items():
            if on_progress:
                on_progress(f"{label(path)} -> {name}")
            out.append((label(path), name, probe_server(name, cfg, timeout=timeout)))
    return out


def live_findings(
    probes: list[tuple[str, str, LiveResult]],
    locked_live: dict[str, Any] | None,
    scan_text: Callable[[str, str], list[Finding]],
    scan_manifest: Callable[[str, str], list[Finding]],
) -> list[Finding]:
    findings: list[Finding] = []
    owners: dict[str, list[str]] = {}

    for file_label, server, res in probes:
        where = f"{file_label}#{server}"
        if not res.ok:
            if res.transport != "skipped":
                findings.append(_f("AMG025", where, f"Server '{server}' was not verified live: {res.error}"))
            continue

        # what the server really advertises goes through the same text and schema rules
        manifest = json.dumps({"tools": res.tools, "prompts": res.prompts}, ensure_ascii=False, indent=2)
        findings.extend(scan_text(f"{where} (live)", manifest))
        findings.extend(scan_manifest(f"{where} (live)", manifest))

        for t in res.tools:
            owners.setdefault(str(t.get("name", "")), []).append(server)

        if locked_live is None:
            continue
        pinned = locked_live.get(where)
        current = res.fingerprint()
        if pinned is None:
            findings.append(
                _f("AMG009", where, f"Server '{server}' is not pinned live yet (run `lock --live`).", Severity.MEDIUM)
            )
            continue
        old_tools: dict[str, Any] = pinned.get("tools", {})
        new_tools: dict[str, Any] = current["tools"]
        for name in sorted(set(new_tools) - set(old_tools)):
            findings.append(_f("AMG009", where, f"New tool '{name}' appeared on '{server}' after approval.", Severity.HIGH))
        for name in sorted(set(old_tools) - set(new_tools)):
            findings.append(_f("AMG009", where, f"Tool '{name}' disappeared from '{server}'.", Severity.LOW))
        for name in sorted(set(old_tools) & set(new_tools)):
            o, n = old_tools[name], new_tools[name]
            if o.get("description_sha256") != n.get("description_sha256"):
                findings.append(
                    _f("AMG009", where, f"Rug pull: description of tool '{name}' on '{server}' changed after approval.", Severity.CRITICAL)
                )
            elif o.get("schema_sha256") != n.get("schema_sha256"):
                findings.append(_f("AMG009", where, f"Parameters of tool '{name}' on '{server}' changed after approval.", Severity.HIGH))
            elif o.get("sha256") != n.get("sha256"):
                findings.append(_f("AMG009", where, f"Metadata of tool '{name}' on '{server}' changed after approval.", Severity.MEDIUM))
        if pinned.get("prompts_sha256") and pinned.get("prompts_sha256") != current["prompts_sha256"]:
            findings.append(_f("AMG009", where, f"Prompts published by '{server}' changed after approval.", Severity.HIGH))

    for tool, servers in sorted(owners.items()):
        distinct = sorted(set(servers))
        if tool and len(distinct) > 1:
            findings.append(
                _f("AMG024", "live", f"Tool '{tool}' is published by {len(distinct)} servers: {', '.join(distinct)}.")
            )
    return findings


def live_lock_entries(probes: list[tuple[str, str, LiveResult]]) -> dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries: dict[str, Any] = {}
    for file_label, server, res in probes:
        if res.ok:
            entries[f"{file_label}#{server}"] = {"probed_at": stamp, "transport": res.transport, **res.fingerprint()}
    return entries
