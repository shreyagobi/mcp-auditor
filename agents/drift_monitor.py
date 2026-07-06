"""
drift_monitor.py — Drift Monitor Agent (Step 3 of pipeline).

A static scan only proves a server was clean at the moment you scanned
it. A "rug pull" server passes that scan, then changes its tool
descriptions or schemas afterward — nothing in Recon or the Semantic
Analyzer alone can catch this, because they only ever see one snapshot.

This agent closes that gap:
  1. `baseline` — recon a server now, hash each tool's description +
     input schema, store it as the trusted snapshot.
  2. `check` — recon the same server again, diff against the stored
     baseline. Any tool whose description or schema changed gets
     reported as drift. Changed tools are automatically re-run through
     the Semantic Analyzer, since a rug pull's whole point is
     introducing something newly malicious.

Baselines are stored per server (keyed by server_name) as JSON under
state/baselines/.

Usage:
    python3 agents/drift_monitor.py baseline servers/rug_pull_server.py
    python3 agents/drift_monitor.py check servers/rug_pull_server.py

Demo (see rug_pull_server.py docstring for the full walkthrough):
    python3 agents/drift_monitor.py baseline servers/rug_pull_server.py
    # (Windows) $env:RUG_PULL="1"
    # (bash)    export RUG_PULL=1
    python3 agents/drift_monitor.py check servers/rug_pull_server.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon import recon_sync  # noqa: E402
from semantic_analyzer import MCPKnowledgeBase, analyze_tool  # noqa: E402

BASELINE_DIR = Path(__file__).resolve().parent.parent / "state" / "baselines"


def _tool_hash(tool: dict[str, Any]) -> str:
    payload = json.dumps(
        {"description": tool["description"], "input_schema": tool.get("input_schema", {})},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class DriftEvent:
    tool_name: str
    change_type: Literal["new_tool", "removed_tool", "description_or_schema_changed"]
    old_description: str | None
    new_description: str | None


def _baseline_path(server_name: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in server_name)
    return BASELINE_DIR / f"{safe_name}.json"


def take_baseline(server_command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    """Recon the server now and persist it as the trusted baseline."""
    recon_report = recon_sync(server_command, env=env)
    server_name = recon_report["server_name"]

    snapshot = {
        "server_name": server_name,
        "server_command": server_command,
        "tools": {
            t["name"]: {
                "hash": _tool_hash(t),
                "description": t["description"],
                "input_schema": t.get("input_schema", {}),
            }
            for t in recon_report["tools"]
        },
    }

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(server_name)
    path.write_text(json.dumps(snapshot, indent=2))
    return snapshot


def check_drift(
    server_command: list[str],
    env: dict[str, str] | None = None,
    reanalyze_changed: bool = True,
) -> dict[str, Any]:
    """Recon the server now and diff against its stored baseline.

    Raises FileNotFoundError if no baseline exists yet — you must call
    take_baseline() first.
    """
    recon_report = recon_sync(server_command, env=env)
    server_name = recon_report["server_name"]

    path = _baseline_path(server_name)
    if not path.exists():
        raise FileNotFoundError(
            f"No baseline found for server '{server_name}'. "
            f"Run take_baseline() / 'drift_monitor.py baseline ...' first."
        )
    baseline = json.loads(path.read_text())

    current_tools = {t["name"]: t for t in recon_report["tools"]}
    baseline_tools = baseline["tools"]

    events: list[DriftEvent] = []

    for name, tool in current_tools.items():
        if name not in baseline_tools:
            events.append(
                DriftEvent(
                    tool_name=name,
                    change_type="new_tool",
                    old_description=None,
                    new_description=tool["description"],
                )
            )
        elif _tool_hash(tool) != baseline_tools[name]["hash"]:
            events.append(
                DriftEvent(
                    tool_name=name,
                    change_type="description_or_schema_changed",
                    old_description=baseline_tools[name]["description"],
                    new_description=tool["description"],
                )
            )

    for name in baseline_tools:
        if name not in current_tools:
            events.append(
                DriftEvent(
                    tool_name=name,
                    change_type="removed_tool",
                    old_description=baseline_tools[name]["description"],
                    new_description=None,
                )
            )

    reanalysis = []
    if reanalyze_changed and events:
        kb = MCPKnowledgeBase()
        kb.seed()
        changed_names = {
            e.tool_name for e in events if e.change_type != "removed_tool"
        }
        for tool in recon_report["tools"]:
            if tool["name"] in changed_names:
                finding = analyze_tool(tool, kb)
                reanalysis.append(asdict(finding))

    return {
        "server_name": server_name,
        "drift_detected": len(events) > 0,
        "events": [asdict(e) for e in events],
        "reanalysis_of_changed_tools": reanalysis,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("baseline", "check"):
        print("Usage:")
        print("  python3 agents/drift_monitor.py baseline <server_script.py>")
        print("  python3 agents/drift_monitor.py check <server_script.py>")
        sys.exit(1)

    mode = sys.argv[1]
    cmd = [sys.executable] + sys.argv[2:]
    # Full env passthrough here is appropriate ONLY because these are our
    # own trusted local test fixtures (e.g. the RUG_PULL toggle). Never
    # do this against a real third-party audit target.
    env = dict(os.environ)

    if mode == "baseline":
        snap = take_baseline(cmd, env=env)
        print(f"Baseline stored for '{snap['server_name']}' "
              f"({len(snap['tools'])} tools) at {_baseline_path(snap['server_name'])}")
    else:
        result = check_drift(cmd, env=env)
        print(f"\n=== Drift Check: {result['server_name']} ===\n")
        if not result["drift_detected"]:
            print("No drift detected — matches baseline.")
        else:
            for e in result["events"]:
                print(f"[{e['change_type'].upper()}] {e['tool_name']}")
                if e["old_description"]:
                    print(f"    OLD: {e['old_description'][:100]}")
                if e["new_description"]:
                    print(f"    NEW: {e['new_description'][:100]}")
                print()
            if result["reanalysis_of_changed_tools"]:
                print("--- Re-analysis of changed tools ---\n")
                for f in result["reanalysis_of_changed_tools"]:
                    flag = "🚩 FLAGGED" if f["flagged"] else "  clean"
                    print(f"[{flag}] {f['tool_name']}")
                    print(f"    verdict: {f['owasp_code']} — {f['owasp_category']} "
                          f"(confidence: {f['confidence']})")
                    print(f"    reasoning: {f['reasoning']}")
                    print()
