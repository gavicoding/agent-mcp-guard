"""Tests for JSON, SARIF 2.1.0, Markdown, Terminal, and HTML reporters."""

import json
import unittest
from pathlib import Path

from agent_mcp_guard.reporters import render_html, render_json, render_markdown, render_sarif, render_terminal
from agent_mcp_guard.scanner import scan_path


class TestReporters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vuln = Path(__file__).resolve().parents[1] / "samples" / "vulnerable-workspace"
        cls.report = scan_path(vuln, lockfile_path=vuln / "mcp-guard.lock.json")

    def test_sarif_schema_valid(self):
        raw = render_sarif(self.report, lang="en")
        data = json.loads(raw)
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "agent-mcp-guard")
        self.assertGreaterEqual(len(run["tool"]["driver"]["rules"]), 20)
        self.assertGreater(len(run["results"]), 5)

    def test_json_pt_localization(self):
        data = json.loads(render_json(self.report, lang="pt"))
        self.assertEqual(data["language"], "pt")
        self.assertGreater(data["risk_score"], 50)
        self.assertTrue(all("remediation" in f and f["remediation"] for f in data["findings"]))

    def test_html_and_markdown_contain_zero_unmasked_keys(self):
        html_out = render_html(self.report, lang="pt")
        md_out = render_markdown(self.report, lang="en")
        term_out = render_terminal(self.report, lang="en", no_color=True)
        self.assertIn("filterSev", html_out)
        self.assertIn("agent-mcp-guard", md_out)
        self.assertIn("AMG009", term_out)
        self.assertNotIn("demo_key_not_real_0123456789abcdef", html_out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", md_out)


if __name__ == "__main__":
    unittest.main()
