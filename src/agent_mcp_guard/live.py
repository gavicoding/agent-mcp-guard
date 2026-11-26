"""Live MCP probing: start (stdio) or call (HTTP) each server, ask for tools/list, prompts/list
and resources/list, and fingerprint what the server really advertises.

This is opt-in (`--live`) because starting a stdio server runs its code on this machine.
Only standard MCP JSON-RPC methods are called; no tool is ever invoked.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .lockfile import normalize_server, sha256_obj

PROTOCOL_VERSION = "2025-06-18"
ENV_REF = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}|\$env:([A-Za-z_][A-Za-z0-9_]*)")
UNRESOLVABLE = re.compile(r"\$\{input:[^}]+\}")
MAX_LINE = 4 * 1024 * 1024


@dataclass
class LiveResult:
    server: str
    ok: bool
    transport: str
    error: str = ""
    server_info: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)

    def fingerprint(self) -> dict[str, Any]:
        """What goes into the lockfile: one hash per tool plus the description hash."""
        tools = {}
        for t in self.tools:
            name = str(t.get("name", ""))
            tools[name] = {
                "sha256": sha256_obj({k: t.get(k) for k in ("name", "title", "description", "inputSchema", "annotations")}),
                "description_sha256": sha256_obj(str(t.get("description", ""))),
                "schema_sha256": sha256_obj(t.get("inputSchema")),
            }
        return {
            "tools": tools,
            "prompts_sha256": sha256_obj(sorted((str(p.get("name")), str(p.get("description", ""))) for p in self.prompts)),
            "resources_sha256": sha256_obj(sorted(str(r.get("uri", "")) for r in self.resources)),
            "server_name": str(self.server_info.get("name", "")),
        }


def _resolve(value: str, env: dict[str, str]) -> str | None:
    """Expand ${VAR} / ${env:VAR}; None when it needs interactive input."""
    if UNRESOLVABLE.search(value):
        return None
    return ENV_REF.sub(lambda m: env.get(m.group(1) or m.group(2), ""), value)


class _Rpc:
    def __init__(self) -> None:
        self.next_id = 1

    def msg(self, method: str, params: dict[str, Any] | None = None, notify: bool = False) -> dict[str, Any]:
        m: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            m["params"] = params
        if not notify:
            m["id"] = self.next_id
            self.next_id += 1
        return m


def _init_params() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "agent-mcp-guard", "version": __version__},
    }


def _paginate(call, method: str, key: str, limit: int = 20) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    for _ in range(limit):
        res = call(method, {"cursor": cursor} if cursor else {})
        if not isinstance(res, dict):
            break
        page = res.get(key)
        if isinstance(page, list):
            items.extend(x for x in page if isinstance(x, dict))
        cursor = res.get("nextCursor")
        if not cursor:
            break
    return items


# ---------------- stdio ----------------


def _probe_stdio(name: str, cfg: dict[str, Any], timeout: float, env_base: dict[str, str]) -> LiveResult:
    command = str(cfg.get("command") or "")
    args = [str(a) for a in cfg.get("args", [])]
    env = dict(env_base)
    for k, v in (cfg.get("env") or {}).items():
        val = _resolve(str(v), env_base)
        if val is None:
            return LiveResult(name, False, "stdio", error=f"env {k} needs interactive input")
        env[str(k)] = val
    resolved_args = []
    for a in args:
        val = _resolve(a, env_base)
        if val is None:
            return LiveResult(name, False, "stdio", error="arguments need interactive input")
        resolved_args.append(val)
    exe = shutil.which(command, path=env.get("PATH")) or command
    cwd = cfg.get("cwd") if isinstance(cfg.get("cwd"), str) and os.path.isdir(str(cfg.get("cwd"))) else None
    creation = subprocess.CREATE_NO_WINDOW if sys.platform.startswith("win") else 0  # type: ignore[attr-defined]
    try:
        proc = subprocess.Popen(
            [exe, *resolved_args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=cwd,
            creationflags=creation,
        )
    except (OSError, ValueError) as exc:
        return LiveResult(name, False, "stdio", error=f"could not start: {exc}")

    lines: queue.Queue[bytes | None] = queue.Queue()

    def reader() -> None:
        assert proc.stdout is not None
        try:
            for raw in iter(lambda: proc.stdout.readline(MAX_LINE), b""):
                lines.put(raw)
        finally:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    rpc = _Rpc()
    deadline = time.monotonic() + timeout

    def send(m: dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(m) + "\n").encode("utf-8"))
        proc.stdin.flush()

    def call(method: str, params: dict[str, Any] | None = None) -> Any:
        m = rpc.msg(method, params)
        send(m)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no answer to {method} within {timeout:.0f}s")
            try:
                raw = lines.get(timeout=left)
            except queue.Empty:
                continue
            if raw is None:
                raise ConnectionError("server exited")
            try:
                reply = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue  # servers sometimes log to stdout
            if isinstance(reply, dict) and reply.get("id") == m["id"]:
                if "error" in reply:
                    raise RuntimeError(str(reply["error"].get("message", reply["error"])))
                return reply.get("result")

    result = LiveResult(name, False, "stdio")
    try:
        init = call("initialize", _init_params())
        caps = init.get("capabilities", {}) if isinstance(init, dict) else {}
        result.server_info = init.get("serverInfo", {}) if isinstance(init, dict) else {}
        send(rpc.msg("notifications/initialized", notify=True))
        if "tools" in caps or not caps:
            result.tools = _paginate(call, "tools/list", "tools")
        if "prompts" in caps:
            result.prompts = _paginate(call, "prompts/list", "prompts")
        if "resources" in caps:
            result.resources = _paginate(call, "resources/list", "resources")
        result.ok = True
    except Exception as exc:  # noqa: BLE001 - every failure becomes a finding, never a crash
        result.error = str(exc)[:300]
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=3)
        except Exception:  # noqa: BLE001
            proc.kill()
    return result


# ---------------- HTTP (streamable) ----------------


def _parse_http_body(body: bytes, content_type: str, want_id: int) -> Any:
    text = body.decode("utf-8", errors="replace")
    candidates: list[Any] = []
    if "text/event-stream" in content_type:
        for block in text.split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in block.splitlines() if line.startswith("data:"))
            if data:
                try:
                    candidates.append(json.loads(data))
                except json.JSONDecodeError:
                    pass
    else:
        try:
            parsed = json.loads(text)
            candidates.extend(parsed if isinstance(parsed, list) else [parsed])
        except json.JSONDecodeError:
            pass
    for c in candidates:
        if isinstance(c, dict) and c.get("id") == want_id:
            if "error" in c:
                raise RuntimeError(str(c["error"].get("message", c["error"])))
            return c.get("result")
    raise RuntimeError("no JSON-RPC answer in HTTP response")


def _probe_http(name: str, cfg: dict[str, Any], timeout: float, env_base: dict[str, str]) -> LiveResult:
    url = _resolve(str(cfg.get("url") or ""), env_base)
    if not url:
        return LiveResult(name, False, "http", error="url needs interactive input")
    if not url.lower().startswith(("http://", "https://")):
        return LiveResult(name, False, "http", error="only http(s) URLs are probed")
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    for k, v in (cfg.get("headers") or {}).items():
        val = _resolve(str(v), env_base)
        if val is None:
            return LiveResult(name, False, "http", error=f"header {k} needs interactive input")
        headers[str(k)] = val
    rpc = _Rpc()
    session: dict[str, str] = {}

    def post(m: dict[str, Any]) -> tuple[bytes, str]:
        h = dict(headers)
        h.update(session)
        req = urllib.request.Request(url, data=json.dumps(m).encode("utf-8"), headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL comes from the user's own config
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                session["Mcp-Session-Id"] = sid
            return resp.read(MAX_LINE), resp.headers.get("Content-Type", "")

    def call(method: str, params: dict[str, Any] | None = None) -> Any:
        m = rpc.msg(method, params)
        body, ctype = post(m)
        return _parse_http_body(body, ctype, m["id"])

    result = LiveResult(name, False, "http")
    try:
        init = call("initialize", _init_params())
        caps = init.get("capabilities", {}) if isinstance(init, dict) else {}
        result.server_info = init.get("serverInfo", {}) if isinstance(init, dict) else {}
        session["MCP-Protocol-Version"] = str(init.get("protocolVersion") or PROTOCOL_VERSION) if isinstance(init, dict) else PROTOCOL_VERSION
        try:
            post(rpc.msg("notifications/initialized", notify=True))
        except urllib.error.HTTPError as exc:
            if exc.code not in (202, 204):
                raise
        if "tools" in caps or not caps:
            result.tools = _paginate(call, "tools/list", "tools")
        if "prompts" in caps:
            result.prompts = _paginate(call, "prompts/list", "prompts")
        if "resources" in caps:
            result.resources = _paginate(call, "resources/list", "resources")
        result.ok = True
    except urllib.error.HTTPError as exc:
        result.error = "needs sign-in (HTTP 401/403)" if exc.code in (401, 403) else f"HTTP {exc.code}"
        exc.close()
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:300]
    return result


def probe_server(name: str, raw_cfg: dict[str, Any], timeout: float = 30.0, env: dict[str, str] | None = None) -> LiveResult:
    cfg = normalize_server(raw_cfg)
    env_base = dict(os.environ if env is None else env)
    if cfg.get("disabled") is True or cfg.get("enabled") is False:
        return LiveResult(name, False, "skipped", error="server is disabled in the config")
    if cfg.get("url"):
        return _probe_http(name, cfg, timeout, env_base)
    if cfg.get("command"):
        return _probe_stdio(name, cfg, timeout, env_base)
    return LiveResult(name, False, "unknown", error="no command or url")
