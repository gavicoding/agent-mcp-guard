# Changelog

## v1.1.0 (2026-11-26)

- `scan --system`: one command checks the global configs of Claude Desktop, Claude Code, Cursor, Windsurf, VS Code (+ Cline, Roo Code), Codex CLI, Gemini CLI, Zed, Amazon Q, Kiro, LM Studio, opencode and Continue on Windows, macOS and Linux. New `where` command lists the paths.
- `--live` for `scan`, `lock` and `verify`: starts stdio servers and calls HTTP servers (streamable HTTP, SSE answers), reads `tools/list`, `prompts/list` and `resources/list`, runs every text rule on what the server really advertises and pins per-tool fingerprints. Rug pulls are now detected on the real server, not only on exported manifests. No tool is ever called.
- New rules: `AMG021` risky hooks, `AMG022` over-broad permission allowlists, `AMG023` auto-trusted project MCP servers, `AMG024` tool name collisions across live servers, `AMG025` live verification gaps. `AMG008` now also reads structured settings (bypassPermissions, Gemini trust, VS Code autoApprove, Codex danger-full-access).
- Config formats: JSON with comments and trailing commas (VS Code, Zed), Codex TOML, `~/.claude.json` per-project servers, Zed `context_servers`, opencode `mcp`, Continue lists.
- Fewer false alarms: a quoted "ignore previous instructions" inside a sentence that tells the agent to refuse it is now low; permission rules such as `Bash(chmod 600 ~/.ssh/config)` are no longer read as credential exfiltration.
- Privacy: from `~/.claude.json` only the MCP server blocks are inspected (the file also stores prompt history); report paths are shown as `~/...`.
- Web workbench: hooks/permissions checks, JSONC parsing and a new "Agent settings" scenario. Portuguese texts rewritten with proper accents.
- Windows `.exe` attached to releases.

## v1.0.0 (2026-11-25)

- Initial public release of `agent-mcp-guard`.
- Added 20 detection rules (`AMG001` - `AMG020`) mapped to OWASP Top 10 for Agentic Apps, MITRE ATLAS, and CWE.
- Added canonical SHA-256 lockfile generator (`lock`) and rug-pull drift verifier (`verify`).
- Added Terminal, JSON, SARIF 2.1.0, Markdown, and interactive HTML reporters with EN/PT-BR localization.
- Added GitHub Action (`action.yml`) and 100% browser-side web workbench (`docs/`).
