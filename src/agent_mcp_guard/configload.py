"""Tolerant loaders for agent/MCP config files: JSON, JSON with comments (JSONC) and TOML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    _toml = None


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings (VS Code / Zed style)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    # trailing commas: , followed by whitespace then } or ]
    result: list[str] = []
    in_str = False
    j = 0
    while j < len(cleaned):
        ch = cleaned[j]
        if in_str:
            result.append(ch)
            if ch == "\\" and j + 1 < len(cleaned):
                result.append(cleaned[j + 1])
                j += 2
                continue
            if ch == '"':
                in_str = False
            j += 1
            continue
        if ch == '"':
            in_str = True
        elif ch == ",":
            k = j + 1
            while k < len(cleaned) and cleaned[k] in " \t\r\n":
                k += 1
            if k < len(cleaned) and cleaned[k] in "}]":
                result.append(" ")
                j += 1
                continue
        result.append(ch)
        j += 1
    return "".join(result)


def load_config_text(path: Path, text: str) -> Any | None:
    """Parse a config file body. Returns None when it cannot be parsed."""
    if path.suffix.lower() == ".toml":
        if _toml is None:
            return None
        try:
            return _toml.loads(text)
        except Exception:
            return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(strip_jsonc(text))
    except json.JSONDecodeError:
        return None


def toml_supported() -> bool:
    return _toml is not None
