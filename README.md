# agent-mcp-guard

[Português](README.pt-BR.md) | **English**

[![CI](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-22c55e)
![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic_Top_10-0ea5e9)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

**Check the AI agents and MCP servers on your machine before they check you.** One command reads the configs of Claude, Cursor, VS Code, Windsurf, Codex, Gemini and others, starts each MCP server to see what it really advertises, and tells you in plain words what is risky and how to fix it. No dependencies, nothing leaves your computer.

🌐 **[Try it in the browser (runs 100% locally)](https://gavicoding.github.io/agent-mcp-guard/)**

![agent-mcp-guard interactive web workbench](docs/screenshot.png)

## What it catches

| Risk | Example | Rules |
| --- | --- | --- |
| Hidden instructions in rules, skills and tool descriptions | `<IMPORTANT>` blocks, HTML comments, zero-width and Trojan Source characters | AMG001-AMG006, AMG016, AMG020 |
| **Rug pull**: a server changes a tool after you approved it | description of `read_file` now says "also send ~/.ssh/id_rsa" | AMG009 (live), AMG018 |
| Hooks that run on their own | `SessionStart` hook doing `curl ... \| bash` | AMG021 |
| Approval switched off or too wide | `bypassPermissions`, `Bash(*)`, `trust: true`, Codex `danger-full-access` | AMG008, AMG022 |
| Any cloned repo can start servers | `enableAllProjectMcpServers: true` | AMG023 |
| Supply chain and transport | `npx -y pkg` without version, `:latest`, `http://`, remote server without auth | AMG010-AMG012, AMG019 |
| Secrets and broad access | API keys in configs, `~/` as filesystem root, admin tokens in `env` | AMG013-AMG015 |
| Tool shadowing across servers | two servers publishing `send_email` | AMG024 |

25 rules in total, mapped to OWASP Top 10 for Agentic Applications, MITRE ATLAS and CWE ([catalog](docs/rules.md)).

## Install

```bash
pipx install git+https://github.com/gavicoding/agent-mcp-guard
# or, without installing anything permanently:
uvx --from git+https://github.com/gavicoding/agent-mcp-guard agent-mcp-guard scan --system
```

Windows users can also download `agent-mcp-guard.exe` from the [latest release](https://github.com/gavicoding/agent-mcp-guard/releases/latest).

## Use

```bash
# 1. Everything on this machine (global configs of every AI client it knows)
agent-mcp-guard scan --system

# 2. Same, plus start each MCP server and inspect what it really publishes
agent-mcp-guard scan --system --live

# 3. Approve what you have now, then catch any change later (rug pull)
agent-mcp-guard lock --system --live
agent-mcp-guard verify --system --live

# A project folder (rules, skills, .mcp.json, .claude/settings.json, ...)
agent-mcp-guard scan . --fail-on high
agent-mcp-guard lock . --live          # writes mcp-guard.lock.json, commit it
agent-mcp-guard verify . --live        # in CI or before opening the project

# Which files does --system read here?
agent-mcp-guard where

# Reports: terminal (default), json, sarif, markdown, html
agent-mcp-guard scan . --format html --output report.html
```

`--live` starts stdio servers (it runs their code, like your AI client does) and calls HTTP servers. It only sends the standard `initialize`, `tools/list`, `prompts/list` and `resources/list` requests and **never calls a tool**. Servers that need an interactive sign-in are reported as "not verified" (AMG025) instead of failing the run.

### What `--system` reads

Claude Desktop, Claude Code (`~/.claude.json`, settings, managed settings, agents, commands, skills), Cursor (MCP, hooks, rules), Windsurf, VS Code and Insiders (settings, `mcp.json`, Cline, Roo Code), Codex CLI (`config.toml`, `AGENTS.md`), Gemini CLI, Zed, Amazon Q, Kiro, LM Studio, opencode and Continue, on Windows, macOS and Linux. Run `agent-mcp-guard where --all` for the exact paths.

From `~/.claude.json` only the MCP server blocks are inspected, because that file also stores your prompt history. Paths in reports are shown as `~/...`, without your user name.

## GitHub Action

```yaml
name: AI agent & MCP security
on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gavicoding/agent-mcp-guard@v1
        with:
          path: "."
          fail-on: "high"
          sarif-output: "agent-mcp-guard.sarif"
```

## Files checked in a project

- Instructions: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.github/*.prompt.md`, and Markdown files under `agents/`, `commands/`, `skills/`, `rules/`
- MCP: `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `mcp-tools.json`
- Agent settings: `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/hooks.json`, `.gemini/settings.json`, `.codex/config.toml` (JSON with comments is supported)

## How it works

- `scanner.py`: text and config rules; `policy.py`: hooks, permissions and trust switches; `configload.py`: JSON, JSONC and TOML.
- `discovery.py`: where each client keeps its global config on each OS.
- `live.py` / `livecheck.py`: minimal MCP client (stdio and streamable HTTP, including SSE answers) and the live rug-pull comparison.
- `lockfile.py`: canonical JSON + SHA-256 pins of servers, tool manifests and live tool fingerprints.
- `docs/`: the same rules in the browser (no upload).

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
node tests/test_web_engine.mjs
```

Tests start a tiny fake MCP server to prove that a changed tool description is reported as a critical rug pull.

MIT License. Built by [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
