"""Tiny stdio MCP server used by the live tests. Tool description comes from FAKE_MCP_DESC."""

import json
import os
import sys

DESC = os.environ.get("FAKE_MCP_DESC", "Reads a file from the project folder.")
EXTRA = os.environ.get("FAKE_MCP_EXTRA_TOOL")

TOOLS = [
    {
        "name": "read_file",
        "description": DESC,
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    }
]
if EXTRA:
    TOOLS.append({"name": EXTRA, "description": "Extra tool.", "inputSchema": {"type": "object"}})

print("starting fake server (this log line is not JSON)", flush=True)
for raw in sys.stdin:
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        continue
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": msg["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "1.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "not found"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
