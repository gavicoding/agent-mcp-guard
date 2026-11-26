"""Find user-level (global) agent and MCP configs on this machine, for `scan --system`.

Only well-known file locations are read. Nothing is uploaded anywhere.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    client: str
    path: Path
    kind: str  # "mcp" | "settings" | "instructions"


def _app_dirs(home: Path, env: dict[str, str], platform: str) -> dict[str, Path]:
    if platform.startswith("win"):
        appdata = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
        return {"config": appdata, "claude_desktop": appdata / "Claude", "zed": appdata / "Zed"}
    if platform == "darwin":
        sup = home / "Library" / "Application Support"
        return {"config": sup, "claude_desktop": sup / "Claude", "zed": home / ".config" / "zed"}
    xdg = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    return {"config": xdg, "claude_desktop": xdg / "Claude", "zed": xdg / "zed"}


def _managed_dirs(env: dict[str, str], platform: str) -> list[Path]:
    if platform.startswith("win"):
        return [Path(env.get("ProgramData") or "C:/ProgramData") / "ClaudeCode"]
    if platform == "darwin":
        return [Path("/Library/Application Support/ClaudeCode")]
    return [Path("/etc/claude-code")]


def candidate_locations(
    home: Path | None = None, env: dict[str, str] | None = None, platform: str | None = None
) -> list[Location]:
    """Every location we know about, existing or not (used by `where`)."""
    home = home or Path.home()
    env = dict(os.environ if env is None else env)
    platform = platform or sys.platform
    d = _app_dirs(home, env, platform)
    out: list[Location] = []

    def add(client: str, path: Path, kind: str) -> None:
        out.append(Location(client, path, kind))

    # Claude Desktop / Claude Code
    add("Claude Desktop", d["claude_desktop"] / "claude_desktop_config.json", "mcp")
    add("Claude Code", home / ".claude.json", "mcp")
    add("Claude Code", home / ".claude" / "settings.json", "settings")
    add("Claude Code", home / ".claude" / "settings.local.json", "settings")
    add("Claude Code", home / ".claude" / "CLAUDE.md", "instructions")
    for m in _managed_dirs(env, platform):
        add("Claude Code (managed)", m / "managed-settings.json", "settings")
        add("Claude Code (managed)", m / "managed-mcp.json", "mcp")
    # Cursor
    add("Cursor", home / ".cursor" / "mcp.json", "mcp")
    add("Cursor", home / ".cursor" / "hooks.json", "settings")
    # Windsurf
    add("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "mcp")
    add("Windsurf", home / ".codeium" / "windsurf" / "memories" / "global_rules.md", "instructions")
    # VS Code (+ Insiders) and extensions that keep their own MCP list
    for flavor in ("Code", "Code - Insiders", "VSCodium"):
        user = d["config"] / flavor / "User"
        add(f"VS Code ({flavor})", user / "settings.json", "settings")
        add(f"VS Code ({flavor})", user / "mcp.json", "mcp")
        gs = user / "globalStorage"
        add(f"Cline ({flavor})", gs / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json", "mcp")
        add(f"Roo Code ({flavor})", gs / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json", "mcp")
    # Codex CLI
    add("Codex CLI", home / ".codex" / "config.toml", "settings")
    add("Codex CLI", home / ".codex" / "AGENTS.md", "instructions")
    # Gemini CLI
    add("Gemini CLI", home / ".gemini" / "settings.json", "settings")
    add("Gemini CLI", home / ".gemini" / "GEMINI.md", "instructions")
    # Others
    add("Zed", d["zed"] / "settings.json", "settings")
    add("Amazon Q", home / ".aws" / "amazonq" / "mcp.json", "mcp")
    add("Kiro", home / ".kiro" / "settings" / "mcp.json", "mcp")
    add("LM Studio", home / ".lmstudio" / "mcp.json", "mcp")
    add("opencode", home / ".config" / "opencode" / "opencode.json", "mcp")
    add("Continue", home / ".continue" / "config.json", "mcp")
    return out


def _glob_instructions(home: Path) -> list[Location]:
    out: list[Location] = []
    patterns = [
        ("Claude Code", home / ".claude" / "agents", "*.md"),
        ("Claude Code", home / ".claude" / "commands", "**/*.md"),
        ("Claude Code", home / ".claude" / "skills", "**/SKILL.md"),
        ("Cursor", home / ".cursor" / "rules", "*.mdc"),
    ]
    for client, base, pattern in patterns:
        if base.is_dir():
            for p in sorted(base.glob(pattern))[:500]:
                if p.is_file():
                    out.append(Location(client, p, "instructions"))
    return out


def discover_system(home: Path | None = None, env: dict[str, str] | None = None, platform: str | None = None) -> list[Location]:
    """Existing global config files, de-duplicated, in a stable order."""
    home = home or Path.home()
    seen: set[str] = set()
    found: list[Location] = []
    for loc in candidate_locations(home, env, platform) + _glob_instructions(home):
        try:
            if not loc.path.is_file():
                continue
            key = str(loc.path.resolve()).lower()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        found.append(loc)
    return found


def display_path(path: Path, home: Path | None = None) -> str:
    """Show paths under the home folder as ~/... (no user name in reports)."""
    home = home or Path.home()
    try:
        return "~/" + path.resolve().relative_to(home.resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()
