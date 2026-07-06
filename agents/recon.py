"""
recon.py — Recon Agent.

Connects to a target MCP server (given as a command to launch it, e.g.
["python3", "servers/clean_server.py"]) over stdio using the official MCP
Python SDK, and enumerates:
  - every tool (name, description, input schema)
  - every resource
  - every prompt
  - declared server info (name, version, capabilities)

This is Step 1 of the pipeline. Output is a plain dict/JSON structure
that downstream agents (Static Semantic Analyzer, Reporting) consume —
deliberately framework-agnostic so it's easy to slot into LangGraph
state later without rewriting this module.

Usage:
    python3 agents/recon.py servers/clean_server.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class ToolRecord:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceRecord:
    uri: str
    name: str
    description: str | None = None
    mime_type: str | None = None


@dataclass
class PromptRecord:
    name: str
    description: str | None = None


@dataclass
class ReconReport:
    server_command: list[str]
    server_name: str | None
    server_version: str | None
    tools: list[ToolRecord]
    resources: list[ResourceRecord]
    prompts: list[PromptRecord]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_recon(server_command: list[str], env: dict[str, str] | None = None) -> ReconReport:
    """Launch the target MCP server as a subprocess over stdio, complete
    the MCP handshake, and enumerate its tools/resources/prompts.

    `env`, if omitted, uses the MCP SDK's default filtered environment
    (a small safe subset of vars) rather than fully inheriting the
    auditor's process environment — appropriate when scanning a
    third-party server you don't fully trust. Pass `env=dict(os.environ)`
    explicitly only for your own trusted local test fixtures (e.g. the
    rug_pull_server.py toggle demo), never for a real audit target.
    """

    params = StdioServerParameters(
        command=server_command[0],
        args=server_command[1:],
        env=env,
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()

            server_name = getattr(init_result.serverInfo, "name", None)
            server_version = getattr(init_result.serverInfo, "version", None)

            tools: list[ToolRecord] = []
            try:
                tools_result = await session.list_tools()
                for t in tools_result.tools:
                    tools.append(
                        ToolRecord(
                            name=t.name,
                            description=t.description or "",
                            input_schema=t.inputSchema or {},
                        )
                    )
            except Exception:
                pass  # server may not support tools

            resources: list[ResourceRecord] = []
            try:
                resources_result = await session.list_resources()
                for r in resources_result.resources:
                    resources.append(
                        ResourceRecord(
                            uri=str(r.uri),
                            name=r.name,
                            description=getattr(r, "description", None),
                            mime_type=getattr(r, "mimeType", None),
                        )
                    )
            except Exception:
                pass  # server may not support resources

            prompts: list[PromptRecord] = []
            try:
                prompts_result = await session.list_prompts()
                for p in prompts_result.prompts:
                    prompts.append(
                        PromptRecord(name=p.name, description=getattr(p, "description", None))
                    )
            except Exception:
                pass  # server may not support prompts

            return ReconReport(
                server_command=server_command,
                server_name=server_name,
                server_version=server_version,
                tools=tools,
                resources=resources,
                prompts=prompts,
            )


def recon_sync(server_command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    """Synchronous convenience wrapper for use from non-async code / LangGraph nodes."""
    report = asyncio.run(run_recon(server_command, env=env))
    return report.to_dict()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agents/recon.py <server_script.py> [args...]")
        sys.exit(1)

    cmd = [sys.executable] + sys.argv[1:]
    result = recon_sync(cmd)
    print(json.dumps(result, indent=2))
