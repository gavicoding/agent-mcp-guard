"""Repository-wide quality gates: EN/PT i18n parity, zero em-dashes, and confidentiality check."""

import unittest
from pathlib import Path

from agent_mcp_guard.i18n import RULE_COPY, UI_STRINGS
from agent_mcp_guard.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TERMS = [
    "ret" + "iro",
    "proc" + "fit",
    "farma" + "one",
    "nex" + "us",
    "ekle" + "sia",
    "ed" + "oc",
    "port" + "aria",
    "671/" + "2021",
]


class TestQualityGates(unittest.TestCase):
    def test_rule_and_ui_bilingual_parity(self):
        self.assertEqual(set(UI_STRINGS["en"].keys()), set(UI_STRINGS["pt"].keys()))
        self.assertEqual(set(RULES.keys()), set(RULE_COPY.keys()))
        for rule_id, locs in RULE_COPY.items():
            self.assertIn("en", locs, f"Missing EN copy for {rule_id}")
            self.assertIn("pt", locs, f"Missing PT copy for {rule_id}")
            self.assertEqual(set(locs["en"].keys()), set(locs["pt"].keys()))

    def test_zero_em_dashes_and_zero_confidential_terms(self):
        exts = {".py", ".md", ".html", ".css", ".js", ".mjs", ".yml", ".yaml", ".toml"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() not in exts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("\u2014", text, f"Em-dash found in {path}")
            low = text.lower()
            for term in FORBIDDEN_TERMS:
                self.assertNotIn(term, low, f"Forbidden term '{term}' in {path}")


if __name__ == "__main__":
    unittest.main()
