"""
reporting.py — Reporting Agent (Step 4 of pipeline).

Takes the outputs of the Semantic Analyzer (and, optionally, the Drift
Monitor) for a server and synthesizes them into one severity-scored
report, mapped to OWASP MCP Top 10 categories. This is the artifact you'd
actually hand to someone — a security lead, or an interviewer — instead
of a wall of raw JSON.

Severity heuristic (documented, not hidden, since "why is this high vs
critical" is exactly what an interviewer will ask):
  - CRITICAL: flagged AND introduced via drift (a rug pull caught live —
    the server was clean at baseline and is not anymore)
  - HIGH:     flagged, high confidence
  - MEDIUM:   flagged, medium confidence
  - LOW:      flagged, low confidence
  - (clean tools are omitted from the findings table, counted in summary)

Usage:
    python3 agents/reporting.py servers/tool_poisoning_server.py
    python3 agents/reporting.py servers/tool_poisoning_server.py --out report.md
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from semantic_analyzer import analyze_server  # noqa: E402

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _severity(finding: dict[str, Any], drift_introduced: bool) -> str | None:
    if not finding["flagged"]:
        return None
    if drift_introduced:
        return "critical"
    return {"high": "high", "medium": "medium", "low": "low"}.get(finding["confidence"], "low")


def generate_report(
    analysis: dict[str, Any],
    drift_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine a semantic_analyzer.analyze_server() result with an
    optional drift_monitor.check_drift() result into one report."""

    drift_flagged_names = set()
    if drift_result and drift_result.get("drift_detected"):
        drift_flagged_names = {
            f["tool_name"] for f in drift_result["reanalysis_of_changed_tools"] if f["flagged"]
        }

    scored_findings = []
    for f in analysis["findings"]:
        sev = _severity(f, drift_introduced=f["tool_name"] in drift_flagged_names)
        if sev is not None:
            scored_findings.append(
                {
                    "tool_name": f["tool_name"],
                    "severity": sev,
                    "owasp_code": f["owasp_code"],
                    "owasp_category": f["owasp_category"],
                    "confidence": f["confidence"],
                    "reasoning": f["reasoning"],
                    "via_drift": f["tool_name"] in drift_flagged_names,
                }
            )

    scored_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    total_tools = len(analysis["findings"])
    flagged_count = len(scored_findings)

    category_counts: dict[str, int] = {}
    for f in scored_findings:
        key = f["owasp_code"] or "uncategorized"
        category_counts[key] = category_counts.get(key, 0) + 1

    return {
        "server_name": analysis["server_name"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "kb_backend": analysis["kb_backend"],
        "total_tools_scanned": total_tools,
        "flagged_count": flagged_count,
        "clean_count": total_tools - flagged_count,
        "category_counts": category_counts,
        "drift_checked": drift_result is not None,
        "drift_detected": bool(drift_result and drift_result.get("drift_detected")),
        "findings": scored_findings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# MCP Security Audit Report — {report['server_name']}",
        "",
        f"**Scanned:** {report['scanned_at']}",
        f"**Knowledge base backend:** {report['kb_backend']}",
        f"**Tools scanned:** {report['total_tools_scanned']} "
        f"({report['flagged_count']} flagged, {report['clean_count']} clean)",
        "",
    ]

    if report["drift_checked"]:
        drift_line = (
            "⚠️ **Drift detected since baseline** — see CRITICAL findings below."
            if report["drift_detected"]
            else "No drift detected since baseline."
        )
        lines += [drift_line, ""]

    if report["category_counts"]:
        lines.append("## Findings by OWASP MCP category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|---|---|")
        for code, count in sorted(report["category_counts"].items()):
            lines.append(f"| {code} | {count} |")
        lines.append("")

    if report["findings"]:
        lines.append("## Detailed findings")
        lines.append("")
        for f in report["findings"]:
            badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(
                f["severity"], "⚪"
            )
            lines.append(f"### {badge} {f['severity'].upper()} — `{f['tool_name']}`")
            lines.append(f"- **Category:** {f['owasp_code']} — {f['owasp_category']}")
            lines.append(f"- **Confidence:** {f['confidence']}")
            if f["via_drift"]:
                lines.append("- **Detected via:** drift monitor (introduced after baseline)")
            lines.append(f"- **Reasoning:** {f['reasoning']}")
            lines.append("")
    else:
        lines.append("## Detailed findings")
        lines.append("")
        lines.append("No vulnerabilities flagged.")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agents/reporting.py <server_script.py> [--out report.md]")
        sys.exit(1)

    out_path = None
    args = sys.argv[1:]
    if "--out" in args:
        idx = args.index("--out")
        out_path = args[idx + 1]
        args = args[:idx] + args[idx + 2:]

    cmd = [sys.executable] + args
    analysis = analyze_server(cmd)
    report = generate_report(analysis)

    md = render_markdown(report)
    print(md)

    if out_path:
        Path(out_path).write_text(md)
        print(f"\n[written to {out_path}]")
