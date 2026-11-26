"""Structured checks for agent settings: hooks that run automatically, approval bypass,
over-broad permission allowlists and auto-trusted project MCP servers.

Covers Claude Code (settings.json), Cursor (hooks.json), Gemini CLI (settings.json),
Codex CLI (config.toml) and VS Code (settings.json).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

from .models import Finding, Severity
from .rules import RULES

HOOK_NETWORK_RX = re.compile(
    r"(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|nc|ncat|netcat|scp|sftp|ftp|telnet)\b|/dev/tcp/"
)
HOOK_EXEC_RX = re.compile(
    r"(?i)\|\s*(sh|bash|zsh|pwsh|powershell|python3?|node)\b|\b(iex|invoke-expression|eval)\b|"
    r"base64\s+(-d|--decode)|frombase64string|\s-(enc|encodedcommand)\s"
)
HOOK_SECRET_RX = re.compile(
    r"(?i)(\.ssh|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|\.netrc|\.npmrc|\.pypirc|keychain|"
    r"login data|cookies|wallet|gh auth token|security find-generic-password)"
)
HOOK_DESTROY_RX = re.compile(r"(?i)\brm\s+-rf?\s+[~/]|remove-item\s+.*-recurse|\bformat\s+[a-z]:|\bdel\s+/[sq]")

SHELL_TOOLS = {"bash", "shell", "run_shell_command", "terminal", "powershell", "cmd"}


def _walk_hooks(data: Any) -> Iterator[tuple[str, str]]:
    """Yield (event, command) for Claude Code and Cursor style hook blocks."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("command"), str):  # Cursor: {"command": "..."}
                yield str(event), entry["command"]
            for inner in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
                if isinstance(inner, dict) and isinstance(inner.get("command"), str):  # Claude Code
                    yield str(event), inner["command"]


def _line_of(text: str, needle: str) -> int:
    if not needle:
        return 1
    idx = text.find(needle[:60])
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _clip(s: str, n: int = 140) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 3] + "..."


def _finding(rule_id: str, rel: str, line: int, evidence: str, severity: Severity | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity or RULES[rule_id].severity,
        file_path=rel,
        line=line,
        column=1,
        evidence=evidence,
    )


def check_hooks(rel: str, text: str, data: Any) -> list[Finding]:
    """AMG021: hooks run shell commands automatically on every session/tool call."""
    out: list[Finding] = []
    for event, command in _walk_hooks(data):
        reasons = []
        net = bool(HOOK_NETWORK_RX.search(command))
        exe = bool(HOOK_EXEC_RX.search(command))
        if net:
            reasons.append("network access")
        if exe:
            reasons.append("dynamic/encoded execution")
        if HOOK_SECRET_RX.search(command):
            reasons.append("touches credential files")
        if HOOK_DESTROY_RX.search(command):
            reasons.append("destructive command")
        if not reasons:
            continue
        sev = Severity.CRITICAL if (net and exe) or len(reasons) >= 2 else Severity.HIGH
        out.append(
            _finding(
                "AMG021",
                rel,
                _line_of(text, command),
                f"Hook '{event}' runs automatically ({', '.join(reasons)}): {_clip(command)}",
                sev,
            )
        )
    return out


def _allow_entries(data: Any) -> list[str]:
    perms = data.get("permissions") if isinstance(data, dict) else None
    if not isinstance(perms, dict):
        return []
    allow = perms.get("allow")
    return [str(a) for a in allow] if isinstance(allow, list) else []


def check_permissions(rel: str, text: str, data: Any) -> list[Finding]:
    """AMG008 (structured approval bypass) and AMG022 (over-broad allowlists)."""
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out

    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    mode = str(perms.get("defaultMode") or "")
    if mode == "bypassPermissions":
        out.append(
            _finding(
                "AMG008",
                rel,
                _line_of(text, "defaultMode"),
                "permissions.defaultMode = bypassPermissions: every tool runs without asking.",
                Severity.HIGH,
            )
        )
    for entry in _allow_entries(data):
        norm = entry.replace(" ", "")
        low = norm.lower()
        tool = low.split("(", 1)[0]
        inner = low[len(tool) + 1 : -1] if "(" in low and low.endswith(")") else None
        unrestricted_shell = tool in SHELL_TOOLS and (inner is None or inner in ("*", ":*", "**"))
        if low in ("*", "mcp__*") or unrestricted_shell:
            out.append(
                _finding(
                    "AMG022",
                    rel,
                    _line_of(text, entry),
                    f"permissions.allow contains '{entry}': unrestricted {'shell' if unrestricted_shell else 'tool'} access without confirmation.",
                    Severity.HIGH,
                )
            )
        elif inner is not None and tool in SHELL_TOOLS and re.fullmatch(r"(curl|wget|python3?|node|npx|bash|sh|pwsh|powershell)(:\*|\*|\s\*)?", inner):
            out.append(
                _finding(
                    "AMG022",
                    rel,
                    _line_of(text, entry),
                    f"permissions.allow contains '{entry}': lets the agent run arbitrary {inner.split(':')[0]} code without asking.",
                )
            )
        elif tool in ("webfetch", "fetch") and (inner is None or inner in ("*", "domain:*")):
            out.append(
                _finding(
                    "AMG022",
                    rel,
                    _line_of(text, entry),
                    f"permissions.allow contains '{entry}': agent can send data to any website without asking.",
                    Severity.MEDIUM,
                )
            )

    # Gemini CLI / VS Code / generic auto-approve switches
    for key, label in (
        ("autoAccept", "autoAccept"),
        ("yolo", "yolo"),
        ("chat.tools.autoApprove", "chat.tools.autoApprove"),
        ("chat.tools.global.autoApprove", "chat.tools.global.autoApprove"),
    ):
        val = data.get(key)
        if val is None and isinstance(data.get("tools"), dict):
            val = data["tools"].get(key)
        if val is True:
            out.append(
                _finding("AMG008", rel, _line_of(text, key), f"{label} = true: tool calls are approved automatically.", Severity.HIGH)
            )

    # Gemini CLI: per-server "trust": true skips all confirmations
    servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else {}
    for name, cfg in servers.items():
        if isinstance(cfg, dict) and cfg.get("trust") is True:
            out.append(
                _finding("AMG008", rel, _line_of(text, f'"{name}"'), f"MCP server '{name}' has trust = true: its tools never ask for confirmation.")
            )

    # Codex CLI config.toml (top level and profiles)
    blocks: list[tuple[str, dict]] = [("", data)]
    if isinstance(data.get("profiles"), dict):
        blocks += [(f"profiles.{k}.", v) for k, v in data["profiles"].items() if isinstance(v, dict)]
    for prefix, blk in blocks:
        approval = str(blk.get("approval_policy") or "")
        sandbox = str(blk.get("sandbox_mode") or "")
        if approval == "never" and sandbox == "danger-full-access":
            out.append(
                _finding(
                    "AMG008",
                    rel,
                    _line_of(text, "approval_policy"),
                    f"{prefix}approval_policy = never with {prefix}sandbox_mode = danger-full-access: no sandbox and no confirmation.",
                    Severity.CRITICAL,
                )
            )
        elif sandbox == "danger-full-access":
            out.append(
                _finding("AMG008", rel, _line_of(text, "sandbox_mode"), f"{prefix}sandbox_mode = danger-full-access: commands run outside the sandbox.")
            )
    return out


def check_project_trust(rel: str, text: str, data: Any) -> list[Finding]:
    """AMG023: MCP servers declared by any cloned repo are enabled without review."""
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    if data.get("enableAllProjectMcpServers") is True:
        out.append(
            _finding(
                "AMG023",
                rel,
                _line_of(text, "enableAllProjectMcpServers"),
                "enableAllProjectMcpServers = true: any repository you open can start its own MCP servers without asking.",
            )
        )
    if data.get("chat.mcp.autostart") in (True, "newAndOutdated"):
        out.append(
            _finding("AMG023", rel, _line_of(text, "chat.mcp.autostart"), "chat.mcp.autostart is on: workspace MCP servers start automatically.", Severity.LOW)
        )
    return out


def is_settings_like(path: Path) -> bool:
    """Files whose structure may carry hooks/permissions."""
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    if name in ("settings.json", "settings.local.json", "managed-settings.json"):
        return True
    if name == "hooks.json" and ".cursor" in parts:
        return True
    if name == "config.toml" and ".codex" in parts:
        return True
    return False


def check_settings(rel: str, path: Path, text: str, data: Any) -> list[Finding]:
    if data is None:
        return []
    findings = check_hooks(rel, text, data)
    if is_settings_like(path):
        findings += check_permissions(rel, text, data)
        findings += check_project_trust(rel, text, data)
    return findings
