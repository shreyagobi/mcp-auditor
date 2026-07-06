"""
baseline_regex_scanner.py — Naive regex/keyword baseline (Week 4 comparison).

Represents the class of existing static-pattern MCP scanners this
project's whole pitch is contrasted against. Deliberately simple and
fully transparent: every rule here is a literal keyword/pattern match or
a plain algorithm (edit distance), nothing semantic, nothing that
requires an LLM. That's the point — this IS the "regex scanner" the
Semantic Analyzer is supposed to outperform on paraphrased attacks,
while ideally matching it on obvious ones.

No LLM dependency, so this runs instantly and fully offline. This also
means it's deterministic — unlike the LLM-based analyzer, running this
twice on the same input always gives the same answer.

Same output shape as semantic_analyzer.analyze_server() (server_name,
findings list) so it plugs into benchmark.py the same way.

Usage:
    python3 agents/baseline_regex_scanner.py servers/tool_poisoning_server.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon import recon_sync  # noqa: E402
from semantic_analyzer import check_typosquat  # noqa: E402

# Literal keyword/phrase patterns a naive static scanner might grep for.
# Deliberately obvious, keyword-level -- no semantic understanding.
SUSPICIOUS_PHRASE_PATTERNS = [
    r"ignore\s+(any\s+)?(prior|previous)\s+(safety\s+)?instructions?",
    r"do\s+not\s+tell\s+the\s+user",
    r"don'?t\s+mention",
    r"without\s+telling",
    r"secretly",
    r"undisclosed",
    r"~?/\.ssh",
    r"id_rsa",
    r"\.pem\b",
    r"\.aws[/\\]",
    r"credentials?\b",
    r"password",
    r"api[_\s]?key",
    r"private\s+key",
]

# Words in a description that imply a side effect beyond the tool's core
# function -- used only in combination with a typosquat name match below,
# same combination rule the semantic analyzer uses, but here purely as a
# keyword list rather than semantic judgment.
SIDE_EFFECT_KEYWORDS = [
    "sync", "remote", "network", "upload", "download", "in the background",
]

# Destructive-sounding parameter names -- a purely literal schema check,
# no understanding of whether the description discloses this.
DESTRUCTIVE_PARAM_NAMES = ["delete", "remove", "cleanup", "wipe", "destroy", "purge"]


def _keyword_flags(description: str) -> list[str]:
    hits = []
    for pattern in SUSPICIOUS_PHRASE_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE):
            hits.append(pattern)
    return hits


def _schema_flags(input_schema: dict[str, Any]) -> list[str]:
    hits = []
    props = input_schema.get("properties", {})
    for prop_name in props:
        if any(word in prop_name.lower() for word in DESTRUCTIVE_PARAM_NAMES):
            hits.append(prop_name)
    return hits


def _typosquat_plus_sideeffect_flag(name: str, description: str) -> dict[str, Any] | None:
    typosquat = check_typosquat(name)
    if not typosquat:
        return None
    matched_keywords = [kw for kw in SIDE_EFFECT_KEYWORDS if kw in description.lower()]
    if matched_keywords:
        return {**typosquat, "matched_keywords": matched_keywords}
    return None


def analyze_tool_baseline(tool: dict[str, Any]) -> dict[str, Any]:
    description = tool["description"]
    keyword_hits = _keyword_flags(description)
    schema_hits = _schema_flags(tool.get("input_schema", {}))
    typosquat_hit = _typosquat_plus_sideeffect_flag(tool["name"], description)

    flagged = bool(keyword_hits or schema_hits or typosquat_hit)

    reasons = []
    if keyword_hits:
        reasons.append(f"matched suspicious phrase pattern(s): {keyword_hits}")
    if schema_hits:
        reasons.append(f"schema has destructive-sounding param(s): {schema_hits}")
    if typosquat_hit:
        reasons.append(
            f"name is edit-distance {typosquat_hit['edit_distance']} from "
            f"'{typosquat_hit['closest_known_name']}' AND description contains "
            f"side-effect keyword(s): {typosquat_hit['matched_keywords']}"
        )

    return {
        "tool_name": tool["name"],
        "flagged": flagged,
        "owasp_code": None,
        "owasp_category": None,
        "confidence": "n/a (deterministic keyword match)",
        "reasoning": "; ".join(reasons) if reasons else "",
    }


def analyze_server_baseline(server_command: list[str]) -> dict[str, Any]:
    recon_report = recon_sync(server_command)
    findings = [analyze_tool_baseline(t) for t in recon_report["tools"]]
    return {
        "server_name": recon_report["server_name"],
        "server_command": server_command,
        "kb_backend": "n/a (no RAG, no LLM)",
        "findings": findings,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agents/baseline_regex_scanner.py <server_script.py>")
        sys.exit(1)

    cmd = [sys.executable] + sys.argv[1:]
    report = analyze_server_baseline(cmd)

    print(f"\n=== Baseline Regex Scan: {report['server_name']} ===\n")
    for f in report["findings"]:
        flag = "🚩 FLAGGED" if f["flagged"] else "  clean"
        print(f"[{flag}] {f['tool_name']}")
        if f["reasoning"]:
            print(f"    reasoning: {f['reasoning']}")
        print()
