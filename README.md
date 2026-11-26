# agent-mcp-guard

[Português](README.pt-BR.md) | **English**

[![CI](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gavicoding/agent-mcp-guard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-22c55e)
![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic_Top_10-0ea5e9)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

**Zero-dependency security scanner, SHA-256 rug-pull guard, and local web workbench for AI agent instructions and Model Context Protocol (MCP) servers.**

🌐 **[Launch Interactive Web Scanner (Runs 100% in your browser)](https://gavicoding.github.io/agent-mcp-guard/)**

![agent-mcp-guard interactive web workbench](docs/screenshot.png)

## Why this exists

AI coding assistants and desktop agents (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `SKILL.md`, `mcp.json`, `claude_desktop_config.json`) execute with developer credentials, SSH keys, and shell permissions. In practice, three supply-chain risks slip past traditional linters:

1. **Tool Poisoning & Prompt Injection:** Hidden `<IMPORTANT>` blocks, HTML comments, zero-width Unicode tags (`U+E0000..U+E007F`), or Trojan Source Bidi markers (`U+202E`) inside rules or MCP tool schemas.
2. **MCP Rug Pulls (Post-Approval Drift):** A remote or unpinned (`npx -y`, `uvx`, `:latest`) MCP server changes a tool description or `inputSchema` silently after you already approved it.
3. **Credential & Privilege Exposure:** Literal API keys, wildcard approvals (`autoApprove: ["*"]`), root filesystem scopes (`/` or `~/`), plaintext remote HTTP endpoints, and unauthenticated remote SSE URLs.

`agent-mcp-guard` catches all 20 attack patterns locally with zero external runtime dependencies, pins MCP servers and tool manifests to a SHA-256 lockfile (`mcp-guard.lock.json`), and exports SARIF 2.1.0 for GitHub Code Scanning.

## Key Capabilities

- **20 Detection Rules (`AMG001` - `AMG020`)** mapped to **OWASP Top 10 for Agentic Applications**, **MITRE ATLAS**, and **CWE** ([full rules catalog](docs/rules.md)).
- **SHA-256 Rug-Pull Lockfile (`lock` / `verify`)**: canonical JSON hashing of server commands, endpoints, tool descriptions, and `inputSchema` objects.
- **Secret Masking by Default (`AMG015`)**: reports flag leaked keys/tokens cleanly with masked prefixes (`AKIAIOSF...[REDACTED]`) so audit artifacts never leak real secrets.
- **Five Output Formats**: colorized Terminal, JSON, **SARIF 2.1.0**, Markdown PR summary, and self-contained interactive HTML report.
- **Bilingual Native (`--lang en` / `--lang pt`)**: idiomatic English and Brazilian Portuguese CLI, HTML reports, and browser UI.
- **Zero-Upload Browser App**: inspect files or verify MCP manifest hashes completely offline on GitHub Pages.

## Quick Start

```bash
# Run bundled vulnerable + hardened demo workspaces
PYTHONPATH=src python -m agent_mcp_guard demo

# Audit your project directory (fails CI on High/Critical findings)
PYTHONPATH=src python -m agent_mcp_guard scan . --fail-on high

# Pin approved MCP servers & tool schemas into mcp-guard.lock.json
PYTHONPATH=src python -m agent_mcp_guard lock .

# Detect silent MCP rug-pull changes in CI or pre-commit
PYTHONPATH=src python -m agent_mcp_guard verify . --lockfile mcp-guard.lock.json

# Export SARIF 2.1.0 + interactive HTML report in Portuguese
PYTHONPATH=src python -m agent_mcp_guard scan . --format html --output mcp-audit.html --lang pt
```

Or install locally via `pip install -e .` and run `agent-mcp-guard scan .`.

## GitHub Action Usage

```yaml
name: AI Agent & MCP Security
on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gavicoding/agent-mcp-guard@v1.0.0
        with:
          path: "."
          fail-on: "high"
          sarif-output: "agent-mcp-guard.sarif"
```

## Supported Files

- `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`
- `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, `.github/copilot-instructions.md`
- `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `mcp-tools.json`

## Architecture

- `src/agent_mcp_guard/scanner.py`: recursive target discovery and 20 deterministic rule detectors.
- `src/agent_mcp_guard/lockfile.py`: canonical JSON normalization + SHA-256 baseline lockfile & drift verifier.
- `src/agent_mcp_guard/reporters.py`: SARIF 2.1.0, HTML, Markdown, JSON, and CLI renderers.
- `docs/`: zero-dependency client-side scanner and Web Crypto SHA-256 Rug-Pull Lab.

## Development & Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
node tests/test_web_engine.mjs
```

MIT License. Built by [Gabriel Souza (@gavicoding)](https://gavicoding.github.io/).
