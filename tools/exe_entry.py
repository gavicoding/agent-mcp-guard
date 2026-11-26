"""Entry point used by PyInstaller to build agent-mcp-guard.exe."""

import sys

from agent_mcp_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
