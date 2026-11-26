"""CLI exit code and subcommand integration tests."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_mcp_guard.cli import main

ROOT = Path(__file__).resolve().parents[1]


class TestCLI(unittest.TestCase):
    def test_rules_subcommand_en_and_pt(self):
        self.assertEqual(main(["rules", "--lang", "en"]), 0)
        self.assertEqual(main(["rules", "--lang", "pt"]), 0)

    def test_scan_hardened_passes_and_vulnerable_fails(self):
        hardened = ROOT / "samples" / "hardened-workspace"
        vuln = ROOT / "samples" / "vulnerable-workspace"
        self.assertEqual(main(["scan", str(hardened), "--fail-on", "low", "--no-color"]), 0)
        self.assertEqual(main(["scan", str(vuln), "--fail-on", "high", "--no-color"]), 1)

    def test_scan_writes_sarif_file_and_module_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif_out = Path(tmp) / "out.sarif"
            vuln = ROOT / "samples" / "vulnerable-workspace"
            code = main(["scan", str(vuln), "--format", "sarif", "--output", str(sarif_out), "--fail-on", "none"])
            self.assertEqual(code, 0)
            parsed = json.loads(sarif_out.read_text(encoding="utf-8"))
            self.assertEqual(parsed["version"], "2.1.0")

        proc = subprocess.run(
            [sys.executable, "-m", "agent_mcp_guard", "demo", "--lang", "pt", "--no-color"],
            cwd=str(ROOT),
            env={"PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
