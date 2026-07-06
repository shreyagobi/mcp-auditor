# Benchmark: comparison against mcp-scan

This compares our RAG + local-LLM auditor against
[`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) (Invariant
Labs) — the most well-known existing MCP security scanner, and the tool
the whole "why is this different from regex" pitch is measured against.

## Important design difference, disclose this in your writeup

`mcp-scan` scans **MCP client config files** (Claude Desktop's config,
Cursor's, etc.) — it doesn't take an arbitrary server script as an
argument the way our `agents/recon.py` does. `mcp_scan_config.json` in
this folder is a minimal client config pointing at our three toy
servers, in the format `mcp-scan` expects, so it can discover and scan
them the same way it would scan a real Claude Desktop install.

## Important privacy difference, also disclose this

By default, `mcp-scan` sends tool names and descriptions to Invariant
Labs' remote API for its guardrail checks — this is the opposite of our
project's fully-local design. Use `--opt-out` to disable the anonymous
ID, but tool descriptions are still shared with their API for scanning
in the default `scan` mode; there is no fully-local mode as of this
writing. This is a legitimate point of comparison for your writeup
("mine is 100% local, theirs requires sending data to a remote API")
but be accurate that it's a design tradeoff, not a flaw in mcp-scan.

## Setup

```bash
# mcp-scan requires uv
pip install uv --break-system-packages   # or see https://docs.astral.sh/uv/
uvx mcp-scan@latest benchmark/mcp_scan_config.json --json > benchmark/mcp_scan_output.json
```

## What to record

For each of the 6 planted vulnerabilities in `servers/ground_truth.json`,
check `mcp_scan_output.json` for whether that specific tool was flagged.
Build a table like:

| Vuln ID | Tool | Our detector | mcp-scan |
|---|---|---|---|
| TP-1 | convert_currency (obvious) | ✅ | ? |
| TP-2 | summarize_document (paraphrased) | ✅ | ? |
| PO-1 | read_file_preview | ✅ | ? |
| PO-2 | git_stauts | ❌ (known limitation) | ? |

The TP-1 vs TP-2 row is the one that actually matters for your pitch —
if mcp-scan catches the obvious payload but misses the paraphrased one,
that's your semantic-vs-pattern-matching claim, measured, not asserted.
If mcp-scan catches both, that's also worth reporting honestly — it
would mean their Guardrails models are already doing some amount of
semantic analysis too, and your differentiator narrows to "fully local"
rather than "semantic vs regex." Either result is useful data; report
whichever one you actually get.
