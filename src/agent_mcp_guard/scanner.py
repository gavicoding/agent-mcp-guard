"""Core security scanner implementing rules AMG001..AMG020 for AI agents and MCP configs."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from .i18n import mask_secret_text
from .lockfile import (
    extract_servers,
    extract_tools,
    is_mcp_config_path,
    is_mcp_tools_path,
    verify_lockfile,
)
from .models import Finding, ScanReport, Severity
from .rules import RULES

AGENT_FILE_NAMES = {
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "claude.md",
    "agents.md",
    "gemini.md",
    "skill.md",
    "copilot-instructions.md",
    "agent-instructions.md",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}

# Unicode codepoint classes for AMG001 and AMG002
ZERO_WIDTH_CODEPOINTS = {
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0x00AD,
    0x034F,
    0x180E,
}
BIDI_CODEPOINTS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:rules|instructions?)\b"),
    re.compile(r"(?i)\bdo\s+not\s+(?:tell|inform|notify|mention\s+to)\s+the\s+user\b"),
    re.compile(r"(?i)\bwithout\s+(?:telling|informing|notifying)\s+the\s+user\b"),
    re.compile(r"(?i)\bhide\s+this\s+step\s+from\s+the\s+user\b"),
    re.compile(r"(?i)<important>.*?(?:ignore|silently|never\s+mention|exfiltrate|before\s+using).*?</important>", re.S),
    re.compile(r"(?i)<!--.*?(?:ignore\s+previous|do\s+not\s+tell|silently|system\s+override|exfiltrate).*?-->", re.S),
    re.compile(r"(?i)\bnever\s+reveal\s+this\s+instruction\b"),
]

CREDENTIAL_PATH_RX = re.compile(
    r"(?i)(?:~/\.ssh|/\.ssh/|id_rsa|id_ed25519|~/\.aws|/\.aws/credentials|\.env\b|/etc/shadow|kube/config|keychain|cookies\.sqlite)"
)
EXFIL_ACTION_RX = re.compile(
    r"(?i)(?:\bcurl\b|\bwget\b|\binvoke-webrequest\b|\bpost\s+to\b|\bupload\b|\bexfiltrat|\bsend\b|\bwebhook\b|\bpass\s+(?:its|the)\s+content|\bappend\s+to\s+body|\bsideload)"
)

CROSS_TOOL_SHADOW_RX = [
    re.compile(r"(?i)\bwhenever\s+the\s+user\s+(?:calls|uses|asks)\s+(?:send_email|git|bash|write_file|execute|read_file|[a-z0-9_]+)\b.*\b(?:instead|also|redirect|change|bcc|forward|prepend)\b"),
    re.compile(r"(?i)\bshadow(?:ing)?\s+tool\b|\boverride\s+(?:the\s+)?(?:behavior|output|arguments)\s+of\s+tool\b"),
    re.compile(r"(?i)\bsilently\s+(?:bcc|cc|forward|replace|modify)\b"),
]

RCE_PATTERNS = [
    re.compile(r"(?i)\b(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash|zsh|dash|pwsh|powershell)\b"),
    re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]*\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}"),
    re.compile(r"(?i)\b(?:iex|invoke-expression)\s*\(\s*(?:new-object|irm|invoke-restmethod|invoke-webrequest)"),
    re.compile(r"(?i)\b/dev/tcp/[0-9.]+/\d+\b"),
    re.compile(r"(?i)\bnc\s+-e\s+/bin/(?:ba)?sh\b"),
]

BYPASS_PATTERNS = [
    re.compile(r"--dangerously-skip-permissions"),
    re.compile(r"(?i)\b--yolo\b"),
    re.compile(r"(?i)[\"']?(?:autoApprove|alwaysAllow)[\"']?\s*:\s*\[\s*[\"']\*[\"']\s*\]"),
    re.compile(r"(?i)[\"']?(?:allow_all_tools|skip_confirmations?|disable_sandbox)[\"']?\s*:\s*true\b"),
]

SECRET_PATTERNS = [
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9]{8,}-[A-Za-z0-9-]{8,}")),
    ("Private key PEM", re.compile(r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE KEY-----")),
    (
        "Assigned secret",
        re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer[_-]?token|webhook[_-]?secret)\b\s*[:=]\s*[\"'](?!\$\{)([A-Za-z0-9_./+=-]{18,})[\"']"),
    ),
]

REMOTE_PROMPT_FETCH_RX = re.compile(
    r"(?i)\b(?:fetch|load|download|read|pull)\s+(?:your\s+)?(?:system\s+)?(?:rules|instructions|prompt|guidelines)\s+from\s+https?://"
)
MARKDOWN_EXFIL_RX = re.compile(
    r"!\[[^\]]*\]\(https?://[^)\s]*(?:\{\{[^}]+\}\}|\$\{[^}]+\}|[?&](?:data|secret|token|q|exfil|leak)=)[^)\s]*\)"
)
BASE64_BLOB_RX = re.compile(r"\b([A-Za-z0-9+/]{36,}={0,2})\b")
SENSITIVE_ENV_NAMES = (
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DATABASE_URL",
    "PRIVATE_KEY",
    "SLACK_BOT_TOKEN",
    "STRIPE_API_KEY",
)
SHELL_META_RX = re.compile(r"(?:&&|\|\||;|`|\$\([^)]+\)|\|)")
BROAD_PATH_VALUES = {"/", "\\", "C:\\", "C:/", "~", "~/", "$HOME", "%USERPROFILE%"}


def is_target_file(path: Path) -> bool:
    """Return True if path matches a known AI agent instruction or MCP manifest file."""
    if not path.is_file():
        return False
    lower_name = path.name.lower()
    lower_parts = [p.lower() for p in path.parts]
    if lower_name in AGENT_FILE_NAMES:
        return True
    if lower_name.endswith(".mdc") and ".cursor" in lower_parts:
        return True
    if is_mcp_config_path(path) or is_mcp_tools_path(path):
        return True
    return False


def discover_target_files(root: Path) -> list[Path]:
    """Walk target path (file or directory) and collect scannable agent/MCP files deterministically."""
    if root.is_file():
        return [root]

    collected: list[Path] = []
    for item in root.rglob("*"):
        if any(part in SKIP_DIRS for part in item.parts):
            continue
        if is_target_file(item):
            collected.append(item)
    return sorted(collected)


def load_workspace_config(root: Path, explicit_config: Path | None = None) -> dict[str, Any]:
    """Load optional `.agent-mcp-guard.json` configuration."""
    cfg_path = explicit_config if explicit_config else (root if root.is_dir() else root.parent) / ".agent-mcp-guard.json"
    if not cfg_path.is_file():
        return {}
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def scan_path(
    target: Path,
    lockfile_path: Path | None = None,
    ignored_rules: set[str] | None = None,
    config_path: Path | None = None,
) -> ScanReport:
    """Run all static rules and optional lockfile verification against a file or directory."""
    root = target if target.is_dir() else target.parent
    cfg = load_workspace_config(root, config_path)
    merged_ignores = set(ignored_rules or set())
    for r in cfg.get("ignore_rules", []):
        merged_ignores.add(str(r).upper())

    files = discover_target_files(target)
    findings: list[Finding] = []
    has_mcp_config = False

    for file_path in files:
        rel_path = _rel_path(root, file_path)
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if is_mcp_config_path(file_path):
            has_mcp_config = True

        findings.extend(_scan_text_content(rel_path, text))

        if is_mcp_config_path(file_path) or is_mcp_tools_path(file_path):
            findings.extend(_scan_mcp_json(rel_path, file_path, text))

    effective_lockfile = lockfile_path
    if effective_lockfile is None and root.is_dir():
        candidate = root / "mcp-guard.lock.json"
        if candidate.is_file():
            effective_lockfile = candidate

    lockfile_checked = False
    if effective_lockfile is not None and effective_lockfile.is_file():
        lockfile_checked = True
        findings.extend(verify_lockfile(effective_lockfile, root, files))
    elif has_mcp_config:
        findings.append(
            Finding(
                rule_id="AMG018",
                severity=RULES["AMG018"].severity,
                file_path=".",
                line=1,
                column=1,
                evidence="MCP config found without a committed mcp-guard.lock.json integrity baseline.",
            )
        )

    filtered = [f for f in findings if f.rule_id not in merged_ignores]
    return ScanReport(
        target=str(target),
        scanned_files=[_rel_path(root, f) for f in files],
        findings=_dedupe_findings(filtered),
        lockfile_path=str(effective_lockfile) if lockfile_checked and effective_lockfile else None,
        lockfile_checked=lockfile_checked,
        ignored_rules=sorted(merged_ignores),
    )


def _scan_text_content(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    # AMG001 & AMG002: line-by-line Unicode stealth inspection
    for line_no, line in enumerate(lines, start=1):
        for col_idx, ch in enumerate(line, start=1):
            cp = ord(ch)
            is_mid_bom = cp == 0xFEFF and not (line_no == 1 and col_idx == 1)
            if cp in ZERO_WIDTH_CODEPOINTS or 0xE0000 <= cp <= 0xE007F or is_mid_bom:
                findings.append(
                    Finding(
                        rule_id="AMG001",
                        severity=RULES["AMG001"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=col_idx,
                        evidence=f"Hidden Unicode char U+{cp:04X} detected in line {line_no}, column {col_idx}.",
                    )
                )
                break
        for col_idx, ch in enumerate(line, start=1):
            cp = ord(ch)
            if cp in BIDI_CODEPOINTS:
                findings.append(
                    Finding(
                        rule_id="AMG002",
                        severity=RULES["AMG002"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=col_idx,
                        evidence=f"Trojan Source Bidi control char U+{cp:04X} detected at line {line_no}:{col_idx}.",
                    )
                )
                break

    # AMG004: Prompt injection & stealth overrides (multi-line safe)
    for rx in PROMPT_INJECTION_PATTERNS:
        for match in rx.finditer(text):
            line_no, col_no = _offset_to_line_col(text, match.start())
            findings.append(
                Finding(
                    rule_id="AMG004",
                    severity=RULES["AMG004"].severity,
                    file_path=rel_path,
                    line=line_no,
                    column=col_no,
                    evidence=_clip_snippet(match.group(0)),
                )
            )

    # AMG005: Credential paths paired with exfiltration verbs within line or nearby block
    for line_no, line in enumerate(lines, start=1):
        if CREDENTIAL_PATH_RX.search(line):
            window_start = max(0, line_no - 2)
            window_end = min(len(lines), line_no + 2)
            neighborhood = "\n".join(lines[window_start:window_end])
            if EXFIL_ACTION_RX.search(neighborhood):
                findings.append(
                    Finding(
                        rule_id="AMG005",
                        severity=RULES["AMG005"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=1,
                        evidence=_clip_snippet(line),
                    )
                )

    # AMG006: Cross-tool shadowing
    for rx in CROSS_TOOL_SHADOW_RX:
        for match in rx.finditer(text):
            line_no, col_no = _offset_to_line_col(text, match.start())
            findings.append(
                Finding(
                    rule_id="AMG006",
                    severity=RULES["AMG006"].severity,
                    file_path=rel_path,
                    line=line_no,
                    column=col_no,
                    evidence=_clip_snippet(match.group(0)),
                )
            )

    # AMG007, AMG008, AMG017, AMG020, AMG015, AMG003
    for line_no, line in enumerate(lines, start=1):
        for rx in RCE_PATTERNS:
            m = rx.search(line)
            if m:
                findings.append(
                    Finding(
                        rule_id="AMG007",
                        severity=RULES["AMG007"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=m.start() + 1,
                        evidence=_clip_snippet(m.group(0)),
                    )
                )
        for rx in BYPASS_PATTERNS:
            m = rx.search(line)
            if m:
                findings.append(
                    Finding(
                        rule_id="AMG008",
                        severity=RULES["AMG008"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=m.start() + 1,
                        evidence=_clip_snippet(m.group(0)),
                    )
                )
        m_remote = REMOTE_PROMPT_FETCH_RX.search(line)
        if m_remote:
            findings.append(
                Finding(
                    rule_id="AMG017",
                    severity=RULES["AMG017"].severity,
                    file_path=rel_path,
                    line=line_no,
                    column=m_remote.start() + 1,
                    evidence=_clip_snippet(line),
                )
            )
        m_md = MARKDOWN_EXFIL_RX.search(line)
        if m_md:
            findings.append(
                Finding(
                    rule_id="AMG020",
                    severity=RULES["AMG020"].severity,
                    file_path=rel_path,
                    line=line_no,
                    column=m_md.start() + 1,
                    evidence=_clip_snippet(m_md.group(0)),
                )
            )
        for label, s_rx in SECRET_PATTERNS:
            m_sec = s_rx.search(line)
            if m_sec and "${" not in m_sec.group(0):
                findings.append(
                    Finding(
                        rule_id="AMG015",
                        severity=RULES["AMG015"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=m_sec.start() + 1,
                        evidence=f"{label}: {mask_secret_text(m_sec.group(0))}",
                    )
                )
        for b_match in BASE64_BLOB_RX.finditer(line):
            decoded = _try_decode_suspicious_b64(b_match.group(1))
            if decoded:
                findings.append(
                    Finding(
                        rule_id="AMG003",
                        severity=RULES["AMG003"].severity,
                        file_path=rel_path,
                        line=line_no,
                        column=b_match.start() + 1,
                        evidence=f"Decoded suspicious Base64 instruction: {_clip_snippet(decoded)}",
                    )
                )

    return findings


def _scan_mcp_json(rel_path: str, file_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    if is_mcp_config_path(file_path):
        for srv_name, cfg in extract_servers(data).items():
            srv_line = _find_key_line(text, srv_name)
            command = str(cfg.get("command") or "")
            args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
            url = str(cfg.get("url") or "")
            headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
            env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}

            # AMG010: Unpinned package or docker :latest
            joined = " ".join([command] + args)
            if re.search(r"(?i)\bnpx\b", command) or "npx" in args:
                pkg = _first_npm_pkg(args)
                if pkg and not re.search(r"@\d+\.\d+", pkg):
                    findings.append(
                        Finding(
                            rule_id="AMG010",
                            severity=RULES["AMG010"].severity,
                            file_path=rel_path,
                            line=srv_line,
                            column=1,
                            evidence=f"Server '{srv_name}' runs unpinned npx package '{pkg}'. Pin package@x.y.z.",
                        )
                    )
            if re.search(r"(?i)\buvx\b", command):
                pkg = _first_uvx_pkg(args)
                if pkg and "==" not in pkg and "@" not in pkg:
                    findings.append(
                        Finding(
                            rule_id="AMG010",
                            severity=RULES["AMG010"].severity,
                            file_path=rel_path,
                            line=srv_line,
                            column=1,
                            evidence=f"Server '{srv_name}' runs unpinned uvx tool '{pkg}'. Pin package==x.y.z.",
                        )
                    )
            if "docker" in command.lower() and ":latest" in joined:
                findings.append(
                    Finding(
                        rule_id="AMG010",
                        severity=RULES["AMG010"].severity,
                        file_path=rel_path,
                        line=srv_line,
                        column=1,
                        evidence=f"Server '{srv_name}' uses unpinned Docker :latest image.",
                    )
                )

            # AMG011: Plaintext non-local URL or 0.0.0.0 bind
            if url.lower().startswith("http://") and not re.match(r"(?i)^http://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?", url):
                findings.append(
                    Finding(
                        rule_id="AMG011",
                        severity=RULES["AMG011"].severity,
                        file_path=rel_path,
                        line=_find_key_line(text, url),
                        column=1,
                        evidence=f"Server '{srv_name}' connects over plaintext non-local HTTP ({url}).",
                    )
                )
            if "0.0.0.0" in url or "0.0.0.0" in joined:
                findings.append(
                    Finding(
                        rule_id="AMG011",
                        severity=RULES["AMG011"].severity,
                        file_path=rel_path,
                        line=srv_line,
                        column=1,
                        evidence=f"Server '{srv_name}' binds 0.0.0.0, exposing MCP on all interfaces.",
                    )
                )

            # AMG012: Remote HTTPS without auth header or oauth config
            if url.lower().startswith("https://") and not re.match(r"(?i)^https://(?:localhost|127\.0\.0\.1)", url):
                header_keys = {k.lower() for k in headers}
                has_auth = bool(header_keys & {"authorization", "x-api-key", "api-key"}) or "oauth" in cfg
                if not has_auth:
                    findings.append(
                        Finding(
                            rule_id="AMG012",
                            severity=RULES["AMG012"].severity,
                            file_path=rel_path,
                            line=_find_key_line(text, url),
                            column=1,
                            evidence=f"Remote HTTPS MCP server '{srv_name}' ({url}) lacks auth headers or OAuth settings.",
                        )
                    )

            # AMG013: Broad filesystem paths
            for arg in args:
                cleaned = arg.strip().strip('"').strip("'")
                if cleaned in BROAD_PATH_VALUES or ".." in cleaned.replace("\\", "/").split("/"):
                    findings.append(
                        Finding(
                            rule_id="AMG013",
                            severity=RULES["AMG013"].severity,
                            file_path=rel_path,
                            line=_find_key_line(text, cleaned),
                            column=1,
                            evidence=f"Server '{srv_name}' exposes broad filesystem scope '{cleaned}'.",
                        )
                    )

            # AMG019: Shell metacharacters in args
            for arg in args:
                if SHELL_META_RX.search(arg):
                    findings.append(
                        Finding(
                            rule_id="AMG019",
                            severity=RULES["AMG019"].severity,
                            file_path=rel_path,
                            line=_find_key_line(text, arg),
                            column=1,
                            evidence=f"Server '{srv_name}' argument contains shell chaining/metacharacters: {_clip_snippet(arg)}",
                        )
                    )

            # AMG014: Sensitive env keys or literal env values
            for env_key, env_val in env.items():
                key_upper = str(env_key).upper()
                val_str = str(env_val)
                if any(tok in key_upper for tok in SENSITIVE_ENV_NAMES) or (
                    any(w in key_upper for w in ("SECRET", "TOKEN", "PASSWORD", "API_KEY"))
                    and not val_str.startswith("${")
                ):
                    findings.append(
                        Finding(
                            rule_id="AMG014",
                            severity=RULES["AMG014"].severity,
                            file_path=rel_path,
                            line=_find_key_line(text, str(env_key)),
                            column=1,
                            evidence=f"Server '{srv_name}' exposes sensitive env variable '{env_key}'.",
                        )
                    )

    if is_mcp_tools_path(file_path):
        for tool_key, schema in extract_tools(data).items():
            desc = str(schema.get("description") or "")
            if len(desc) > 1500:
                findings.append(
                    Finding(
                        rule_id="AMG016",
                        severity=RULES["AMG016"].severity,
                        file_path=rel_path,
                        line=_find_key_line(text, str(schema.get("name") or tool_key)),
                        column=1,
                        evidence=f"Tool '{tool_key}' description has {len(desc)} chars (> 1500 limit).",
                    )
                )

    return findings


def _try_decode_suspicious_b64(blob: str) -> str | None:
    if len(blob) % 4 not in (0, 2, 3):
        return None
    try:
        padded = blob + "=" * ((4 - len(blob) % 4) % 4)
        raw = base64.b64decode(padded, validate=True)
        decoded = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    if len(decoded) < 12:
        return None
    printable_ratio = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t") / len(decoded)
    if printable_ratio < 0.85:
        return None
    if re.search(r"(?i)\b(?:curl|wget|bash|sh\s+-c|powershell|iex|ignore\s+previous|exfiltrate|chmod\s+\+x|https?://)\b", decoded):
        return decoded
    return None


def _first_npm_pkg(args: list[str]) -> str | None:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _first_uvx_pkg(args: list[str]) -> str | None:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _find_key_line(text: str, needle: str) -> int:
    if not needle:
        return 1
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return idx
    return 1


def _offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    col = offset + 1 if last_nl == -1 else offset - last_nl
    return line, col


def _clip_snippet(snippet: str, limit: int = 120) -> str:
    single = " ".join(snippet.split())
    redacted = mask_secret_text(single)
    return redacted if len(redacted) <= limit else redacted[: limit - 3] + "..."


def _rel_path(root: Path, file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return file_path.as_posix()


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line, f.evidence)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return sorted(result, key=lambda item: item.sort_key())
