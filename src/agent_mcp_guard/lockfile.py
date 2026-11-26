"""SHA-256 lockfile generation and rug-pull drift verification for MCP manifests."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .configload import load_config_text
from .models import Finding, Severity

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp_config.json",
    ".claude.json",
    "cline_mcp_settings.json",
    "mcp_settings.json",
    "managed-mcp.json",
    "opencode.json",
}
SETTINGS_PARENTS = (".claude", ".gemini", ".vscode", ".cursor", "user", "zed", "claudecode")
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
    parent = path.parent.name.lower()
    if name in ("settings.json", "settings.local.json", "managed-settings.json") and parent in SETTINGS_PARENTS:
        return True
    if name == "hooks.json" and parent == ".cursor":
        return True
    if name == "config.toml" and parent == ".codex":
        return True
    if name == "config.json" and parent == ".continue":
        return True
    return False


def is_mcp_tools_path(path: Path) -> bool:
    """Identify exported MCP tool manifest files."""
    return path.name.lower() in MCP_TOOLS_NAMES


def extract_servers(data: Any) -> dict[str, Any]:
    """Extract MCP server blocks from every config schema we know.

    mcpServers (Claude/Cursor/Windsurf/Gemini/Cline), servers (VS Code mcp.json),
    mcp.servers (VS Code settings.json), context_servers (Zed), mcp_servers (Codex TOML),
    mcp (opencode), projects[*].mcpServers (~/.claude.json) and Continue's list form.
    """
    if not isinstance(data, dict):
        return {}
    servers: dict[str, Any] = {}

    def take(block: Any, prefix: str = "") -> None:
        if isinstance(block, dict):
            for srv_name, srv_cfg in block.items():
                if isinstance(srv_cfg, dict):
                    servers[f"{prefix}{srv_name}"] = srv_cfg

    for key in ("mcpServers", "servers", "context_servers", "mcp_servers"):
        take(data.get(key))
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        if isinstance(mcp.get("servers"), dict):
            take(mcp["servers"])
        else:
            take({k: v for k, v in mcp.items() if isinstance(v, dict) and any(x in v for x in ("command", "url", "type"))})
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj_path, proj_cfg in projects.items():
            if isinstance(proj_cfg, dict):
                label = Path(str(proj_path).replace("\\", "/")).name or "project"
                take(proj_cfg.get("mcpServers"), prefix=f"[{label}] ")
    exp = data.get("experimental")
    if isinstance(exp, dict) and isinstance(exp.get("modelContextProtocolServers"), list):
        for idx, item in enumerate(exp["modelContextProtocolServers"]):
            if isinstance(item, dict):
                transport = item.get("transport") if isinstance(item.get("transport"), dict) else item
                servers[str(item.get("name") or f"continue_{idx}")] = transport
    return servers


def normalize_server(cfg: dict[str, Any]) -> dict[str, Any]:
    """Same shape for every client: command (str), args (list[str]), env, url, headers."""
    out = dict(cfg)
    command = cfg.get("command")
    if isinstance(command, dict):  # Zed: {"command": {"path": ..., "args": [...], "env": {...}}}
        out["command"] = str(command.get("path") or "")
        out["args"] = list(command.get("args") or [])
        if isinstance(command.get("env"), dict):
            out["env"] = command["env"]
    elif isinstance(command, list):  # opencode: ["npx", "-y", "pkg"]
        out["command"] = str(command[0]) if command else ""
        out["args"] = [str(a) for a in command[1:]] + [str(a) for a in (cfg.get("args") or [])]
    if not isinstance(out.get("args"), list):
        out["args"] = []
    for k in ("env", "environment"):
        if isinstance(cfg.get(k), dict):
            out["env"] = cfg[k]
    if not isinstance(out.get("headers"), dict):
        out["headers"] = cfg.get("http_headers") if isinstance(cfg.get("http_headers"), dict) else {}
    if not out.get("url") and isinstance(cfg.get("serverUrl"), str):  # Windsurf
        out["url"] = cfg["serverUrl"]
    return out


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


def build_lock_entries(root: Path, files: list[Path], label: Callable[[Path], str] | None = None) -> dict[str, Any]:
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
        except Exception:
            continue
        data = load_config_text(file_path, raw)
        if data is None:
            continue

        rel = label(file_path) if label else _rel_path(root, file_path)
        if is_mcp_config_path(file_path):
            for srv_name, srv_cfg in extract_servers(data).items():
                key = f"{rel}#{srv_name}"
                norm = normalize_server(srv_cfg)
                entries["servers"][key] = {
                    "sha256": sha256_obj(srv_cfg),
                    "command": norm.get("command") or norm.get("url") or "",
                    "args": norm.get("args", []),
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


def write_lockfile(
    lockfile_path: Path,
    root: Path,
    files: list[Path],
    label: Callable[[Path], str] | None = None,
    live: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate and persist mcp-guard.lock.json (optionally with live tool fingerprints)."""
    payload = build_lock_entries(root, files, label)
    if live is not None:
        payload["schema_version"] = 2
        payload["live"] = live
    lockfile_path.parent.mkdir(parents=True, exist_ok=True)
    lockfile_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return payload


def verify_lockfile(
    lockfile_path: Path, root: Path, files: list[Path], label: Callable[[Path], str] | None = None
) -> list[Finding]:
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

    current = build_lock_entries(root, files, label)

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
