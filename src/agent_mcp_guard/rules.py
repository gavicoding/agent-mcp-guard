"""Rule definitions mapped to OWASP Top 10 for Agentic Apps, MITRE ATLAS, and CWE."""

from __future__ import annotations

from .models import RuleDefinition, Severity

RULES: dict[str, RuleDefinition] = {
    "AMG001": RuleDefinition(
        rule_id="AMG001",
        severity=Severity.CRITICAL,
        category="unicode-steganography",
        owasp_agentic="ASI01: Agent Goal Hijack",
        mitre_atlas="AML.T0051.000",
        cwe="CWE-172",
    ),
    "AMG002": RuleDefinition(
        rule_id="AMG002",
        severity=Severity.CRITICAL,
        category="trojan-source-bidi",
        owasp_agentic="ASI01: Agent Goal Hijack",
        mitre_atlas="AML.T0051.000",
        cwe="CWE-1007",
    ),
    "AMG003": RuleDefinition(
        rule_id="AMG003",
        severity=Severity.HIGH,
        category="obfuscated-payload",
        owasp_agentic="ASI01: Agent Goal Hijack",
        mitre_atlas="AML.T0051.001",
        cwe="CWE-506",
    ),
    "AMG004": RuleDefinition(
        rule_id="AMG004",
        severity=Severity.CRITICAL,
        category="prompt-injection",
        owasp_agentic="ASI01: Agent Goal Hijack",
        mitre_atlas="AML.T0051.000",
        cwe="CWE-74",
    ),
    "AMG005": RuleDefinition(
        rule_id="AMG005",
        severity=Severity.CRITICAL,
        category="credential-exfiltration",
        owasp_agentic="ASI02: Tool Misuse and Exploitation",
        mitre_atlas="AML.T0057",
        cwe="CWE-200",
    ),
    "AMG006": RuleDefinition(
        rule_id="AMG006",
        severity=Severity.HIGH,
        category="cross-tool-shadowing",
        owasp_agentic="ASI02: Tool Misuse and Exploitation",
        mitre_atlas="AML.T0051.001",
        cwe="CWE-94",
    ),
    "AMG007": RuleDefinition(
        rule_id="AMG007",
        severity=Severity.HIGH,
        category="remote-code-execution",
        owasp_agentic="ASI05: Unexpected Code Execution",
        mitre_atlas="AML.T0010",
        cwe="CWE-78",
    ),
    "AMG008": RuleDefinition(
        rule_id="AMG008",
        severity=Severity.MEDIUM,
        category="excessive-autonomy",
        owasp_agentic="ASI03: Identity and Privilege Abuse",
        mitre_atlas="AML.T0048",
        cwe="CWE-250",
    ),
    "AMG009": RuleDefinition(
        rule_id="AMG009",
        severity=Severity.CRITICAL,
        category="mcp-rug-pull",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010.003",
        cwe="CWE-494",
    ),
    "AMG010": RuleDefinition(
        rule_id="AMG010",
        severity=Severity.HIGH,
        category="unpinned-supply-chain",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010",
        cwe="CWE-829",
    ),
    "AMG011": RuleDefinition(
        rule_id="AMG011",
        severity=Severity.HIGH,
        category="insecure-transport",
        owasp_agentic="ASI07: Insecure Inter-Agent Communication",
        mitre_atlas="AML.T0024",
        cwe="CWE-319",
    ),
    "AMG012": RuleDefinition(
        rule_id="AMG012",
        severity=Severity.HIGH,
        category="unauthenticated-remote-mcp",
        owasp_agentic="ASI03: Identity and Privilege Abuse",
        mitre_atlas="AML.T0048",
        cwe="CWE-306",
    ),
    "AMG013": RuleDefinition(
        rule_id="AMG013",
        severity=Severity.MEDIUM,
        category="broad-filesystem-scope",
        owasp_agentic="ASI02: Tool Misuse and Exploitation",
        mitre_atlas="AML.T0057",
        cwe="CWE-732",
    ),
    "AMG014": RuleDefinition(
        rule_id="AMG014",
        severity=Severity.MEDIUM,
        category="sensitive-env-exposure",
        owasp_agentic="ASI03: Identity and Privilege Abuse",
        mitre_atlas="AML.T0057",
        cwe="CWE-526",
    ),
    "AMG015": RuleDefinition(
        rule_id="AMG015",
        severity=Severity.CRITICAL,
        category="hardcoded-secret",
        owasp_agentic="ASI03: Identity and Privilege Abuse",
        mitre_atlas="AML.T0057",
        cwe="CWE-798",
    ),
    "AMG016": RuleDefinition(
        rule_id="AMG016",
        severity=Severity.MEDIUM,
        category="oversized-tool-schema",
        owasp_agentic="ASI01: Agent Goal Hijack",
        mitre_atlas="AML.T0051.001",
        cwe="CWE-400",
    ),
    "AMG017": RuleDefinition(
        rule_id="AMG017",
        severity=Severity.MEDIUM,
        category="remote-prompt-fetch",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010",
        cwe="CWE-829",
    ),
    "AMG018": RuleDefinition(
        rule_id="AMG018",
        severity=Severity.LOW,
        category="missing-lockfile",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010.003",
        cwe="CWE-353",
    ),
    "AMG019": RuleDefinition(
        rule_id="AMG019",
        severity=Severity.HIGH,
        category="command-injection-args",
        owasp_agentic="ASI05: Unexpected Code Execution",
        mitre_atlas="AML.T0010",
        cwe="CWE-78",
    ),
    "AMG020": RuleDefinition(
        rule_id="AMG020",
        severity=Severity.MEDIUM,
        category="markdown-exfiltration",
        owasp_agentic="ASI02: Tool Misuse and Exploitation",
        mitre_atlas="AML.T0057",
        cwe="CWE-200",
    ),
    "AMG021": RuleDefinition(
        rule_id="AMG021",
        severity=Severity.HIGH,
        category="auto-executed-hook",
        owasp_agentic="ASI05: Unexpected Code Execution",
        mitre_atlas="AML.T0050",
        cwe="CWE-78",
    ),
    "AMG022": RuleDefinition(
        rule_id="AMG022",
        severity=Severity.MEDIUM,
        category="overbroad-permission-allowlist",
        owasp_agentic="ASI03: Identity and Privilege Abuse",
        mitre_atlas="AML.T0048",
        cwe="CWE-250",
    ),
    "AMG023": RuleDefinition(
        rule_id="AMG023",
        severity=Severity.MEDIUM,
        category="auto-trusted-project-servers",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010",
        cwe="CWE-829",
    ),
    "AMG024": RuleDefinition(
        rule_id="AMG024",
        severity=Severity.MEDIUM,
        category="live-tool-name-collision",
        owasp_agentic="ASI02: Tool Misuse and Exploitation",
        mitre_atlas="AML.T0051.001",
        cwe="CWE-694",
    ),
    "AMG025": RuleDefinition(
        rule_id="AMG025",
        severity=Severity.LOW,
        category="live-verification-gap",
        owasp_agentic="ASI04: Agentic Supply Chain Vulnerabilities",
        mitre_atlas="AML.T0010.003",
        cwe="CWE-345",
    ),
}


def get_rule(rule_id: str) -> RuleDefinition:
    """Return rule metadata by rule_id."""
    return RULES[rule_id]


def list_rules() -> list[RuleDefinition]:
    """Return all rule definitions ordered by rule_id."""
    return [RULES[k] for k in sorted(RULES)]
