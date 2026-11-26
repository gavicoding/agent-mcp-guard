"""Reporters for Terminal, JSON, SARIF 2.1.0, Markdown, and self-contained HTML."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from .i18n import t_rule, t_ui
from .models import Finding, ScanReport, Severity
from .rules import RULES, list_rules


def render_report(report: ScanReport, fmt: str, lang: str = "en", no_color: bool = False) -> str:
    """Dispatch output rendering by format."""
    if fmt == "json":
        return render_json(report, lang)
    if fmt == "sarif":
        return render_sarif(report, lang)
    if fmt == "markdown":
        return render_markdown(report, lang)
    if fmt == "html":
        return render_html(report, lang)
    return render_terminal(report, lang, no_color=no_color)


def render_terminal(report: ScanReport, lang: str = "en", no_color: bool = False) -> str:
    """Render concise colorized CLI output."""
    use_color = not no_color
    colors = {
        Severity.CRITICAL: "\033[91m" if use_color else "",
        Severity.HIGH: "\033[31m" if use_color else "",
        Severity.MEDIUM: "\033[33m" if use_color else "",
        Severity.LOW: "\033[36m" if use_color else "",
    }
    reset = "\033[0m" if use_color else ""
    bold = "\033[1m" if use_color else ""

    counts = report.counts_by_severity()
    lines = [
        f"{bold}{t_ui(lang, 'report_title')} v{report.version}{reset}",
        f"{t_ui(lang, 'target_label')}: {report.target} | {t_ui(lang, 'files_scanned')}: {len(report.scanned_files)} | {t_ui(lang, 'risk_score')}: {report.risk_score()}/100",
        f"Summary: Critical={counts['critical']} High={counts['high']} Medium={counts['medium']} Low={counts['low']}",
        "-" * 72,
    ]

    ordered = report.sorted_findings()
    if not ordered:
        lines.append(t_ui(lang, "clean_status"))
        return "\n".join(lines)

    for item in ordered:
        rule_meta = RULES[item.rule_id]
        rule_copy = t_rule(lang, item.rule_id)
        badge = f"{colors[item.severity]}[{item.severity.value.upper()}]{reset}"
        lines.append(f"{badge} {bold}{item.rule_id}{reset} {rule_copy['title']}")
        lines.append(f"  {t_ui(lang, 'location')}: {item.file_path}:{item.line}:{item.column} ({rule_meta.owasp_agentic}, {rule_meta.cwe})")
        lines.append(f"  {t_ui(lang, 'evidence')}: {item.evidence}")
        lines.append(f"  {t_ui(lang, 'remediation')}: {rule_copy['remediation']}")
    return "\n".join(lines)


def render_json(report: ScanReport, lang: str = "en") -> str:
    """Render structured JSON with localized rule metadata and metrics."""
    payload: dict[str, Any] = {
        "tool": "agent-mcp-guard",
        "version": report.version,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "language": lang,
        "target": report.target,
        "scanned_files": report.scanned_files,
        "lockfile_checked": report.lockfile_checked,
        "lockfile_path": report.lockfile_path,
        "risk_score": report.risk_score(),
        "counts": report.counts_by_severity(),
        "findings": [],
    }
    for f in report.sorted_findings():
        meta = RULES[f.rule_id]
        copy = t_rule(lang, f.rule_id)
        entry = f.to_dict()
        entry.update(
            {
                "title": copy["title"],
                "description": copy["description"],
                "remediation": copy["remediation"],
                "owasp_agentic": meta.owasp_agentic,
                "mitre_atlas": meta.mitre_atlas,
                "cwe": meta.cwe,
            }
        )
        payload["findings"].append(entry)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sarif(report: ScanReport, lang: str = "en") -> str:
    """Render SARIF 2.1.0 output compatible with GitHub Code Scanning."""
    rules_arr = []
    for meta in list_rules():
        copy = t_rule(lang, meta.rule_id)
        rules_arr.append(
            {
                "id": meta.rule_id,
                "name": meta.category,
                "shortDescription": {"text": copy["title"]},
                "fullDescription": {"text": copy["description"]},
                "help": {
                    "text": f"{copy['remediation']} ({meta.owasp_agentic}, {meta.mitre_atlas}, {meta.cwe})"
                },
                "defaultConfiguration": {"level": meta.severity.sarif_level},
                "properties": {
                    "tags": ["security", "ai-agent", "mcp", meta.owasp_agentic, meta.cwe],
                    "security-severity": _sarif_security_score(meta.severity),
                },
            }
        )

    results_arr = []
    for f in report.sorted_findings():
        meta = RULES[f.rule_id]
        copy = t_rule(lang, f.rule_id)
        uri = "." if f.file_path in ("", ".") else f.file_path
        results_arr.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f"{copy['title']}: {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column),
                            },
                        }
                    }
                ],
                "properties": {
                    "owasp_agentic": meta.owasp_agentic,
                    "mitre_atlas": meta.mitre_atlas,
                    "cwe": meta.cwe,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-mcp-guard",
                        "version": report.version,
                        "informationUri": "https://github.com/gavicoding/agent-mcp-guard",
                        "rules": rules_arr,
                    }
                },
                "results": results_arr,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def render_markdown(report: ScanReport, lang: str = "en") -> str:
    """Render Markdown summary ideal for PR comments or $GITHUB_STEP_SUMMARY."""
    counts = report.counts_by_severity()
    lines = [
        f"# {t_ui(lang, 'report_title')}",
        "",
        f"- **{t_ui(lang, 'target_label')}:** `{report.target}`",
        f"- **{t_ui(lang, 'files_scanned')}:** {len(report.scanned_files)}",
        f"- **{t_ui(lang, 'risk_score')}:** `{report.risk_score()}/100`",
        f"- **{t_ui(lang, 'lockfile_status')}:** {t_ui(lang, 'lockfile_verified') if report.lockfile_checked else t_ui(lang, 'lockfile_missing')}",
        "",
        f"| {t_ui(lang, 'critical')} | {t_ui(lang, 'high')} | {t_ui(lang, 'medium')} | {t_ui(lang, 'low')} |",
        "|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    ordered = report.sorted_findings()
    if not ordered:
        lines.append(f"> {t_ui(lang, 'clean_status')}")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            f"| {t_ui(lang, 'severity')} | {t_ui(lang, 'rule')} | {t_ui(lang, 'location')} | {t_ui(lang, 'evidence')} | {t_ui(lang, 'remediation')} |",
            "|---|---|---|---|---|",
        ]
    )
    for f in ordered:
        copy = t_rule(lang, f.rule_id)
        ev = f.evidence.replace("|", "\\|").replace("\n", " ")
        rem = copy["remediation"].replace("|", "\\|")
        lines.append(
            f"| **{f.severity.value.upper()}** | `{f.rule_id}` {copy['title']} | `{f.file_path}:{f.line}` | `{ev}` | {rem} |"
        )
    return "\n".join(lines) + "\n"


def render_html(report: ScanReport, lang: str = "en") -> str:
    """Render self-contained interactive HTML report with severity filters."""
    counts = report.counts_by_severity()
    ordered = report.sorted_findings()
    rows_html = []
    for f in ordered:
        meta = RULES[f.rule_id]
        copy = t_rule(lang, f.rule_id)
        sev = f.severity.value
        rows_html.append(
            f"""
            <tr data-severity="{html.escape(sev)}">
              <td><span class="pill pill-{html.escape(sev)}">{html.escape(sev.upper())}</span></td>
              <td><strong>{html.escape(f.rule_id)}</strong><div class="sub">{html.escape(copy['title'])}</div></td>
              <td class="mono">{html.escape(f.file_path)}:{f.line}:{f.column}</td>
              <td><span class="badge">{html.escape(meta.owasp_agentic)}</span><div class="sub">{html.escape(meta.mitre_atlas)} | {html.escape(meta.cwe)}</div></td>
              <td><code>{html.escape(f.evidence)}</code><div class="rem">{html.escape(copy['remediation'])}</div></td>
            </tr>
            """
        )

    table_body = (
        "\n".join(rows_html)
        if rows_html
        else f'<tr><td colspan="5" class="clean-cell">{html.escape(t_ui(lang, "clean_status"))}</td></tr>'
    )
    lock_label = t_ui(lang, "lockfile_verified") if report.lockfile_checked else t_ui(lang, "lockfile_missing")

    return f"""<!DOCTYPE html>
<html lang="{html.escape(lang)}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(t_ui(lang, 'report_title'))}</title>
  <style>
    :root {{ --bg: #0b101b; --card: #121a2b; --border: #24304a; --text: #e6edf7; --muted: #93a4c3; --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #38bdf8; --ok: #22c55e; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 28px; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }}
    .wrap {{ max-width: 1220px; margin: 0 auto; }}
    header {{ margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }}
    h1 {{ margin: 0 0 6px; font-size: 1.65rem; }}
    .muted {{ color: var(--muted); font-size: 0.92rem; }}
    .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .kpi {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
    .kpi-val {{ font-size: 1.65rem; font-weight: 700; }}
    .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }}
    .btn {{ background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 999px; cursor: pointer; font-size: 0.85rem; }}
    .btn.active {{ border-color: #60a5fa; background: #1d2b48; }}
    .table-box {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-weight: 700; font-size: 0.75rem; }}
    .pill-critical {{ background: rgba(239,68,68,.18); color: #fca5a5; border: 1px solid var(--crit); }}
    .pill-high {{ background: rgba(249,115,22,.18); color: #fdba74; border: 1px solid var(--high); }}
    .pill-medium {{ background: rgba(234,179,8,.16); color: #fde047; border: 1px solid var(--med); }}
    .pill-low {{ background: rgba(56,189,248,.16); color: #7dd3fc; border: 1px solid var(--low); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.82rem; }}
    .sub {{ color: var(--muted); font-size: 0.82rem; margin-top: 2px; }}
    .rem {{ color: #86efac; font-size: 0.82rem; margin-top: 6px; }}
    .badge {{ background: #1c2740; border: 1px solid var(--border); border-radius: 6px; padding: 2px 6px; font-size: 0.78rem; display: inline-block; }}
    code {{ background: #0a0e18; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; word-break: break-word; display: inline-block; }}
    .clean-cell {{ color: var(--ok); font-weight: 600; text-align: center; padding: 24px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>{html.escape(t_ui(lang, 'report_title'))}</h1>
      <div class="muted">{html.escape(t_ui(lang, 'report_subtitle'))}</div>
      <div class="muted" style="margin-top:6px;">{html.escape(t_ui(lang, 'target_label'))}: <code>{html.escape(report.target)}</code> | {html.escape(t_ui(lang, 'lockfile_status'))}: <strong>{html.escape(lock_label)}</strong></div>
    </header>
    <section class="kpis">
      <div class="kpi"><div class="muted">{html.escape(t_ui(lang, 'risk_score'))}</div><div class="kpi-val">{report.risk_score()}/100</div></div>
      <div class="kpi"><div class="muted">{html.escape(t_ui(lang, 'files_scanned'))}</div><div class="kpi-val">{len(report.scanned_files)}</div></div>
      <div class="kpi"><div class="muted">{html.escape(t_ui(lang, 'critical'))}</div><div class="kpi-val" style="color:var(--crit)">{counts['critical']}</div></div>
      <div class="kpi"><div class="muted">{html.escape(t_ui(lang, 'high'))}</div><div class="kpi-val" style="color:var(--high)">{counts['high']}</div></div>
      <div class="kpi"><div class="muted">{html.escape(t_ui(lang, 'medium'))} / {html.escape(t_ui(lang, 'low'))}</div><div class="kpi-val">{counts['medium']} / {counts['low']}</div></div>
    </section>
    <div class="filters">
      <button class="btn active" onclick="filterSev('all', this)">{html.escape(t_ui(lang, 'filter_all'))}</button>
      <button class="btn" onclick="filterSev('critical', this)">{html.escape(t_ui(lang, 'critical'))}</button>
      <button class="btn" onclick="filterSev('high', this)">{html.escape(t_ui(lang, 'high'))}</button>
      <button class="btn" onclick="filterSev('medium', this)">{html.escape(t_ui(lang, 'medium'))}</button>
      <button class="btn" onclick="filterSev('low', this)">{html.escape(t_ui(lang, 'low'))}</button>
    </div>
    <div class="table-box">
      <table>
        <thead>
          <tr>
            <th>{html.escape(t_ui(lang, 'severity'))}</th>
            <th>{html.escape(t_ui(lang, 'rule'))}</th>
            <th>{html.escape(t_ui(lang, 'location'))}</th>
            <th>{html.escape(t_ui(lang, 'owasp_mapping'))}</th>
            <th>{html.escape(t_ui(lang, 'evidence'))} &amp; {html.escape(t_ui(lang, 'remediation'))}</th>
          </tr>
        </thead>
        <tbody id="findings-body">
          {table_body}
        </tbody>
      </table>
    </div>
    <p class="muted" style="margin-top:16px;">{html.escape(t_ui(lang, 'generated_by'))} v{html.escape(report.version)}</p>
  </div>
  <script>
    function filterSev(sev, btn) {{
      document.querySelectorAll('.filters .btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('#findings-body tr').forEach(row => {{
        const rowSev = row.getAttribute('data-severity');
        row.style.display = (!rowSev || sev === 'all' || rowSev === sev) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""


def _sarif_security_score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.8",
        Severity.MEDIUM: "5.4",
        Severity.LOW: "2.8",
    }[severity]
