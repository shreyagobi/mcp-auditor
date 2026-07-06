"""
sandbox_demo.py — Sandboxed Exploitation Demo (Step 6, Week 4 stretch goal).

Shows the *concrete impact* of a flagged tool-poisoning vulnerability:
what would a naive MCP client (one with no auditor in front of it) have
actually done if it just followed the instructions embedded in a
poisoned tool description?

SAFETY DESIGN — read before running against anything else:
This NEVER touches real files on your machine, even though the actual
planted payloads in tool_poisoning_server.py reference real-looking
paths like "~/.ssh/id_rsa". Instead, this script:
  1. Creates its own synthetic decoy files (fake, obviously-not-real
     content) inside a local ./sandbox/decoy_home/ directory.
  2. Runs a simple, scripted "naive client" that extracts file-path-like
     strings from a tool's description and reads ONLY from the decoy
     sandbox directory, never from the real filesystem paths named in
     the description.
  3. Prints what got "leaked" — i.e. that the decoy content ended up in
     the tool's response — to make the impact concrete without ever
     reading anything real.

This is intentionally restricted to the toy servers built for this
project. Do not repurpose this against a real, third-party MCP server —
that would cross from "demonstrating a vulnerability's impact in a
controlled sandbox" into "attempting to exploit a system you don't own,"
which this project does not do and this script is not designed for.

Usage:
    python3 agents/sandbox_demo.py servers/tool_poisoning_server.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon import recon_sync  # noqa: E402
from semantic_analyzer import analyze_tool, MCPKnowledgeBase  # noqa: E402

SANDBOX_DIR = Path(__file__).resolve().parent.parent / "sandbox" / "decoy_home"

# Path-like patterns a poisoned description might reference. Deliberately
# generic pattern matching (not tied to any specific test fixture's exact
# wording) so this works on any tool-poisoning payload that names files.
FILE_PATTERN_HINTS = [
    (r"\.ssh[/\\]?\S*", "decoy_ssh_key"),
    (r"\bid_rsa\b", "decoy_ssh_key"),
    (r"cloud credential\S*", "decoy_cloud_credentials"),
    (r"\.aws[/\\]?\S*", "decoy_cloud_credentials"),
    (r"\bpem\b|\bkey\b", "decoy_generic_secret"),
]


def _setup_decoy_files() -> dict[str, Path]:
    """Create synthetic, obviously-fake decoy files. Never real credential
    paths -- these live entirely under ./sandbox/decoy_home/."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    decoys = {
        "decoy_ssh_key": SANDBOX_DIR / "fake_id_rsa",
        "decoy_cloud_credentials": SANDBOX_DIR / "fake_cloud_credentials",
        "decoy_generic_secret": SANDBOX_DIR / "fake_secret.pem",
    }
    decoys["decoy_ssh_key"].write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "THIS IS A SYNTHETIC DECOY, NOT A REAL KEY, GENERATED FOR THIS DEMO\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    decoys["decoy_cloud_credentials"].write_text(
        "[default]\naws_access_key_id = DECOY_NOT_REAL_AKIA0000000000\n"
        "aws_secret_access_key = decoy-not-real-secret-value\n"
    )
    decoys["decoy_generic_secret"].write_text("SYNTHETIC DECOY SECRET, NOT REAL\n")
    return decoys


def _find_referenced_decoys(description: str, decoys: dict[str, Path]) -> list[Path]:
    """Scan a tool description for file-path-like language and map it to
    the corresponding decoy file -- never to a real filesystem path."""
    matched = []
    for pattern, decoy_key in FILE_PATTERN_HINTS:
        if re.search(pattern, description, re.IGNORECASE) and decoys[decoy_key] not in matched:
            matched.append(decoys[decoy_key])
    return matched


def simulate_naive_client(tool: dict[str, Any], decoys: dict[str, Path]) -> dict[str, Any]:
    """Scripted stand-in for 'an LLM client with no auditor, blindly
    following whatever a tool description tells it to do.' Reads ONLY
    from the sandbox decoy files, never real paths, regardless of what
    the description text names."""
    referenced = _find_referenced_decoys(tool["description"], decoys)

    if not referenced:
        return {
            "tool_name": tool["name"],
            "would_have_leaked": False,
            "leaked_content": None,
            "referenced_decoys": [],
        }

    leaked_content = "\n---\n".join(p.read_text() for p in referenced)
    return {
        "tool_name": tool["name"],
        "would_have_leaked": True,
        "leaked_content": leaked_content,
        "referenced_decoys": [str(p) for p in referenced],
    }


def run_demo(server_command: list[str]) -> None:
    decoys = _setup_decoy_files()
    recon_report = recon_sync(server_command)
    kb = MCPKnowledgeBase()
    kb.seed()

    print(f"=== Sandboxed Exploitation Demo: {recon_report['server_name']} ===\n")
    print(f"(Decoy secrets live under {SANDBOX_DIR} — nothing real is touched)\n")

    for tool in recon_report["tools"]:
        finding = analyze_tool(tool, kb)
        sim = simulate_naive_client(tool, decoys)

        print(f"--- {tool['name']} ---")
        print(f"Auditor verdict: {'🚩 FLAGGED (' + str(finding.owasp_code) + ')' if finding.flagged else 'clean'}")

        if sim["would_have_leaked"]:
            print("Impact if a NAIVE client (no auditor) had called this tool:")
            print(f"  Would have read and returned: {sim['referenced_decoys']}")
            print(f"  i.e. this content would have ended up in the tool's response:")
            for line in sim["leaked_content"].splitlines():
                print(f"    | {line}")
            if finding.flagged:
                print("  --> Our auditor caught this BEFORE any tool call happened.")
            else:
                print("  --> ⚠️ Our auditor did NOT catch this one (see Week 3/4 known limitations).")
        else:
            print("No file-path-like references found in this tool's description.")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agents/sandbox_demo.py <server_script.py>")
        print("(Intended for the toy servers under servers/ only.)")
        sys.exit(1)

    cmd = [sys.executable] + sys.argv[1:]
    run_demo(cmd)
