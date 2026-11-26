# Detection Rules Reference (AMG001 - AMG020)

| Rule | Severity | Category | OWASP Agentic / CWE |
|---|---|---|---|
| `AMG001` | Critical | Zero-width / Unicode Tags | ASI01 / CWE-172 |
| `AMG002` | Critical | Trojan Source Bidi Controls | ASI01 / CWE-1007 |
| `AMG003` | High | Obfuscated Base64 Payload | ASI01 / CWE-506 |
| `AMG004` | Critical | Prompt Injection / Stealth Override | ASI01 / CWE-74 |
| `AMG005` | Critical | Credential Exfiltration Directive | ASI02 / CWE-200 |
| `AMG006` | High | Cross-Tool Shadowing | ASI02 / CWE-94 |
| `AMG007` | High | Remote Execution Bootstrap (`curl\|sh`, `iex`) | ASI05 / CWE-78 |
| `AMG008` | Medium | Wildcard Permission Bypass | ASI03 / CWE-250 |
| `AMG009` | Critical | MCP Rug Pull (SHA-256 Lockfile Drift) | ASI04 / CWE-494 |
| `AMG010` | High | Unpinned `npx`, `uvx`, or Docker `:latest` | ASI04 / CWE-829 |
| `AMG011` | High | Plaintext `http://` or `0.0.0.0` Bind | ASI07 / CWE-319 |
| `AMG012` | High | Unauthenticated Remote HTTPS MCP | ASI03 / CWE-306 |
| `AMG013` | Medium | Overly Broad Filesystem Scope | ASI02 / CWE-732 |
| `AMG014` | Medium | Sensitive Environment Variable Exposure | ASI03 / CWE-526 |
| `AMG015` | Critical | Hardcoded API Key / Token / Private Key | ASI03 / CWE-798 |
| `AMG016` | Medium | Oversized MCP Tool Description (> 1500 chars) | ASI01 / CWE-400 |
| `AMG017` | Medium | Dynamic Remote Prompt URL Fetching | ASI04 / CWE-829 |
| `AMG018` | Low | Missing `mcp-guard.lock.json` Lockfile | ASI04 / CWE-353 |
| `AMG019` | High | Shell Metacharacters in MCP `args` | ASI05 / CWE-78 |
| `AMG020` | Medium | Markdown Image / Link Exfiltration Vector | ASI02 / CWE-200 |
