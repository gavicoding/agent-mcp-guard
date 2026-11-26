"""Core data models for agent-mcp-guard findings, rules, lockfiles, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Normalized finding severity levels ordered from highest to lowest risk."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return order[self]

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 14,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
        }
        return weights[self]

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


@dataclass(frozen=True)
class RuleDefinition:
    """Static metadata describing a security detection rule."""

    rule_id: str
    severity: Severity
    category: str
    owasp_agentic: str
    mitre_atlas: str
    cwe: str


@dataclass
class Finding:
    """Single actionable security finding emitted during a scan or lockfile check."""

    rule_id: str
    severity: Severity
    file_path: str
    line: int
    column: int
    evidence: str
    context: dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple[int, str, int, int, str]:
        return (-self.severity.rank, self.file_path, self.line, self.column, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "context": self.context,
        }


@dataclass
class ScanReport:
    """Complete immutable-style summary of a workspace scan."""

    target: str
    scanned_files: list[str]
    findings: list[Finding]
    lockfile_path: str | None = None
    lockfile_checked: bool = False
    ignored_rules: list[str] = field(default_factory=list)
    version: str = "1.0.0"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def risk_score(self) -> int:
        raw = sum(f.severity.weight for f in self.findings)
        return min(100, raw)

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def exceeds_threshold(self, fail_on: str) -> bool:
        if fail_on == "none":
            return False
        threshold = Severity(fail_on)
        return any(f.severity.rank >= threshold.rank for f in self.findings)
