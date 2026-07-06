"""
auditor_mcp_server.py — The auditor, exposed as an MCP server (Week 5 stretch).

Everything so far has been "our client, someone else's server." This
flips it: this project's own detection pipeline (Recon + RAG + Semantic
Analyzer + Reporting) is exposed as an MCP server itself, so any MCP
client — Claude Desktop, Cursor, Claude Code, or this project's own
recon.py — can call it as a tool. The practical use case: before adding
a new, unfamiliar MCP server to your client config, point this auditor
at it first and get a report back, without your primary assistant ever
touching the untrusted server directly.

Run this like any other MCP server (stdio), then point an MCP client at
it. Example Claude Desktop config entry:

    "mcp-security-auditor": {
      "command": "python3",
      "args": ["/absolute/path/to/agents/auditor_mcp_server.py"]
    }

Then in a chat with that client: "use the security auditor to check
whether this new server I'm about to add is safe: <command + args>."

Usage (manual test, same as any other server in this project):
    python3 agents/auditor_mcp_server.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP

from reporting import generate_report, render_markdown  # noqa: E402
from semantic_analyzer import analyze_server  # noqa: E402

mcp = FastMCP("mcp-security-auditor")


@mcp.tool()
def audit_mcp_server(command: str, args: list[str] | None = None) -> str:
    """Audit a target MCP server for tool-poisoning (OWASP MCP03) and
    privilege-escalation/scope-creep (OWASP MCP02) vulnerabilities before
    you trust it.

    Launches the target server, enumerates every tool it declares, and
    uses a RAG-grounded local LLM to judge each tool description for
    hidden instructions, description/schema mismatches, or typosquatting.
    Nothing about the target server or this analysis leaves your machine
    — all inference runs on your local Ollama instance.

    Args:
        command: the executable to launch the target server (e.g. "python3")
        args: arguments to that command (e.g. ["path/to/server.py"])

    Returns:
        A severity-scored Markdown report. Read it before deciding
        whether to actually add this server to your own MCP client config.
    """
    cmd = [command] + list(args or [])
    analysis = analyze_server(cmd)
    report = generate_report(analysis)
    return render_markdown(report)


@mcp.tool()
def quick_verdict(command: str, args: list[str] | None = None) -> str:
    """Faster, one-line-per-tool version of audit_mcp_server for a quick
    yes/no read before deciding whether the full report is worth reading."""
    cmd = [command] + list(args or [])
    analysis = analyze_server(cmd)
    lines = [f"Server: {analysis['server_name']}"]
    for f in analysis["findings"]:
        mark = "FLAGGED" if f["flagged"] else "clean"
        lines.append(f"  [{mark}] {f['tool_name']}"
                     + (f" — {f['owasp_code']}" if f["flagged"] else ""))
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
