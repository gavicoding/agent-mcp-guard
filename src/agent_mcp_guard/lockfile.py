"""SHA-256 lockfile generation and rug-pull drift verification for MCP manifests."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, Severity

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp_config.json",
}
MCP_TOOLS_NAMES = {
    "mcp-tools.json",
    "tools-manifest.json",
}


def canonical_json(obj: Any) -> str:
    """Serialize Python objects deterministically for stable SHA-256 hashing."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def sha256_obj(obj: Any) -> str:
    """Compute SHA-256 hex digest of the canonical JSON representation."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def is_mcp_config_path(path: Path) -> bool:
    """Identify MCP client/server config files across IDEs."""
    name = path.name.lower()
    if name in MCP_CONFIG_NAMES:
        return True
    parts = [p.lower() for p in path.parts]
    if name == "settings.json" and any(p in parts for p in (".claude", ".gemini", ".vscode")):
        return True
    return False


def is_mcp_tools_path(path: Path) -> bool:
    """Identify exported MCP tool manifest files."""
    return path.name.lower() in MCP_TOOLS_NAMES


def extract_servers(data: Any) -> dict[str, Any]:
    """Extract normalized MCP server blocks from standard config schemas."""
    if not isinstance(data, dict):
        return {}
    servers: dict[str, Any] = {}
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for srv_name, srv_cfg in block.items():
                if isinstance(srv_cfg, dict):
                    servers[str(srv_name)] = srv_cfg
    return servers


def extract_tools(data: Any) -> dict[str, dict[str, Any]]:
    """Extract normalized tool schemas keyed by tool name."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        raw = data.get("tools")
        items = raw if isinstance(raw, list) else []
    else:
        return {}

    tools: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(items):
        if isinstance(item, dict):
            name = str(item.get("name") or f"tool_{idx}")
            server = str(item.get("server") or "default")
            full_key = f"{server}::{name}" if "server" in item else name
            tools[full_key] = item
    return tools


def build_lock_entries(root: Path, files: list[Path]) -> dict[str, Any]:
    """Build SHA-256 lock entries for all discovered MCP configs and tool manifests."""
    entries: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "servers": {},
        "tools": {},
    }
    for file_path in sorted(files):
        try:
            raw = file_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            continue

        rel = _rel_path(root, file_path)
        if is_mcp_config_path(file_path):
            for srv_name, srv_cfg in extract_servers(data).items():
                key = f"{rel}#{srv_name}"
                entries["servers"][key] = {
                    "sha256": sha256_obj(srv_cfg),
                    "command": srv_cfg.get("command") or srv_cfg.get("url") or "",
                    "args": srv_cfg.get("args", []),
                }
        if is_mcp_tools_path(file_path):
            for tool_name, tool_schema in extract_tools(data).items():
                key = f"{rel}#{tool_name}"
                entries["tools"][key] = {
                    "sha256": sha256_obj(tool_schema),
                    "description_sha256": hashlib.sha256(
                        str(tool_schema.get("description", "")).encode("utf-8")
                    ).hexdigest(),
                    "description_len": len(str(tool_schema.get("description", ""))),
                }
    return entries


def write_lockfile(lockfile_path: Path, root: Path, files: list[Path]) -> dict[str, Any]:
    """Generate and persist mcp-guard.lock.json."""
    payload = build_lock_entries(root, files)
    lockfile_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return payload


def verify_lockfile(lockfile_path: Path, root: Path, files: list[Path]) -> list[Finding]:
    """Compare current MCP configs and tool schemas against the committed lockfile."""
    findings: list[Finding] = []
    try:
        expected = json.loads(lockfile_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="AMG009",
                severity=Severity.CRITICAL,
                file_path=_rel_path(root, lockfile_path),
                line=1,
                column=1,
                evidence=f"Failed to parse lockfile JSON: {exc}",
            )
        )
        return findings

    current = build_lock_entries(root, files)

    expected_servers = expected.get("servers", {})
    for key, cur_info in current.get("servers", {}).items():
        rel = key.split("#", 1)[0]
        if key not in expected_servers:
            findings.append(
                Finding(
                    rule_id="AMG009",
                    severity=Severity.CRITICAL,
                    file_path=rel,
                    line=1,
                    column=1,
                    evidence=f"Unpinned MCP server '{key.split('#', 1)[1]}' missing from lockfile (new hash {cur_info['sha256'][:12]}).",
                )
            )
        elif expected_servers[key].get("sha256") != cur_info["sha256"]:
            exp_hash = str(expected_servers[key].get("sha256", ""))[:12]
            cur_hash = cur_info["sha256"][:12]
            findings.append(
                Finding(
                    rule_id="AMG009",
                    severity=Severity.CRITICAL,
                    file_path=rel,
                    line=1,
                    column=1,
                    evidence=f"MCP server '{key.split('#', 1)[1]}' hash drifted: expected {exp_hash}..., got {cur_hash}....",
                )
            )

    expected_tools = expected.get("tools", {})
    for key, cur_info in current.get("tools", {}).items():
        rel = key.split("#", 1)[0]
        tool_name = key.split("#", 1)[1]
        if key not in expected_tools:
            findings.append(
                Finding(
                    rule_id="AMG009",
                    severity=Severity.CRITICAL,
                    file_path=rel,
                    line=1,
                    column=1,
                    evidence=f"Unpinned MCP tool '{tool_name}' missing from lockfile (hash {cur_info['sha256'][:12]}).",
                )
            )
        elif expected_tools[key].get("sha256") != cur_info["sha256"]:
            exp_hash = str(expected_tools[key].get("sha256", ""))[:12]
            cur_hash = cur_info["sha256"][:12]
            desc_changed = expected_tools[key].get("description_sha256") != cur_info["description_sha256"]
            reason = "tool description changed silently" if desc_changed else "tool inputSchema changed"
            findings.append(
                Finding(
                    rule_id="AMG009",
                    severity=Severity.CRITICAL,
                    file_path=rel,
                    line=1,
                    column=1,
                    evidence=f"MCP rug pull on '{tool_name}' ({reason}): expected {exp_hash}..., got {cur_hash}....",
                )
            )

    return findings


def _rel_path(root: Path, file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return file_path.as_posix()
