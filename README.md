# MCP Security Auditor

An LLM-powered vulnerability auditor for MCP (Model Context Protocol)
servers. Existing static scanners pattern-match tool descriptions
against known-bad keywords; this project uses a local LLM, grounded by
retrieval against a curated knowledge base of known attack patterns, to
catch semantically-equivalent attacks that don't use any alarming words.

Runs entirely on local infrastructure (Ollama) — no tool descriptions or
scan results leave the machine.

## Architecture

```
Recon Agent          -> connects to a target MCP server, enumerates every
                         tool, resource, and prompt (agents/recon.py)
Semantic Analyzer     -> RAG-retrieves similar known attack patterns per
                         tool, asks a local LLM for a grounded verdict
                         (agents/semantic_analyzer.py, rag/)
Drift Monitor         -> baselines a server, re-checks later, catches
                         post-install "rug pulls" static scans can't see
                         (agents/drift_monitor.py)
Reporting Agent       -> synthesizes findings into a severity-scored,
                         OWASP-mapped report (agents/reporting.py)
Sandboxed Demo        -> shows concrete impact using synthetic decoy
                         files only, never real paths (agents/sandbox_demo.py)
Benchmark             -> precision/recall/F1 against ground truth, plus
                         a transparent regex baseline for comparison
                         (agents/benchmark.py, agents/baseline_regex_scanner.py)
```

Taxonomy: [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10)
(beta/pilot as of mid-2026 — cite as `MCPxx:2025`, not a finalized standard).

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

ollama pull llama3.1:8b          # see "why 8b, not 3b" below
ollama pull nomic-embed-text
ollama serve
```

## Test bed

Five toy MCP servers under `servers/`, each purpose-built for a specific
test:

| Server | Purpose |
|---|---|
| `clean_server.py` | negative control — 0 planted vulns |
| `tool_poisoning_server.py` | 2 planted MCP03 (Tool Poisoning): one obvious, one paraphrased/keyword-free |
| `permission_overreach_server.py` | 2 planted MCP02 (Scope Creep): schema/description mismatch, typosquat+side-effect |
| `token_mismanagement_server.py` | 1 planted MCP01 (Token Mismanagement): plaintext credential requested as a call argument |
| `rug_pull_server.py` | toggles clean↔poisoned via `RUG_PULL` env var, for the Drift Monitor demo |
| `holdout_server.py` | generalization check — never referenced during prompt development |

`servers/ground_truth.json` is the labeled answer key.

## Validated results

All numbers below are from actual runs, not projected.

### Detection rate (agents/benchmark.py, 3 runs x 4 servers)

**Precision: 1.0, Recall: 1.0, F1: 1.0** — 15/15 planted vulnerabilities
caught, 0/30 false positives, using `llama3.1:8b`, fully reproducible
across repeated runs, across three distinct OWASP MCP categories
(MCP01, MCP02, MCP03).

### Why llama3.1:8b, not llama3.2:3b

Measured, not assumed: `llama3.2:3b` missed both tool-poisoning payloads
on this test bed, including the one with explicit "ignore prior
instructions" language — it appears to reflexively sanitize past
injected text rather than analyzing it, even with an explicit
untrusted-data prompt boundary. `llama3.1:8b` caught all planted
vulnerabilities with zero false positives. This is a real, specific
model-size threshold observed on a fixed test bed, not a general claim
about model scaling.

### Baseline comparison (agents/baseline_regex_scanner.py)

A transparent, fully deterministic keyword/regex scanner — no LLM, no
RAG — representing the class of existing static-pattern MCP scanners.
Run head-to-head on the same test bed:

| Vulnerability | Baseline (regex) | This project |
|---|---|---|
| convert_currency — obvious payload | caught | caught |
| summarize_document — paraphrased, no trigger keywords | MISSED | caught |
| read_file_preview — schema/description mismatch | caught | caught |
| git_stauts — typosquat + implied side effect | caught | caught |

Both approaches tie on obvious/structural cases. The one case that
differentiates them — a paraphrased attack using zero alarming
keywords — is exactly the evasion technique a real attacker would use
against a keyword scanner, and it's the one this project catches that
the baseline doesn't. That's the actual, measured claim, not an
assumption.

Note: summarize_document's payload was rewritten once during
benchmarking after an earlier version accidentally contained the literal
word "credentials," which the baseline's keyword list also checks for —
that version tied with the baseline instead of differentiating from it.
Worth stating plainly in any writeup: the first version of this test
wasn't actually fair, and fixing it was part of the process.

### Held-out generalization test

`holdout_server.py`'s `raed_file` tool (typosquat of `read_file`,
disguised as "forwards to a logging endpoint") was never named or
referenced anywhere in `semantic_analyzer.py`'s prompt during
development. It was still correctly flagged, and the clean control tool
in the same server was correctly left unflagged — real evidence the
typosquat-detection approach generalizes rather than memorizing the
known `git_stauts` test case.

The typosquat check itself (`check_typosquat()` in
`semantic_analyzer.py`) is a plain edit-distance algorithm against a
generic list of common tool names, feeding the LLM computed evidence
("edit distance 2 from read_file") rather than a memorized example —
this is what makes the generalization result meaningful rather than
circular.

### Known limitations (state these, don't hide them)

- Edit-distance typosquat detection misses double-transposition typos
  (e.g. sned_emial vs send_email) — Damerau-Levenshtein would fix
  this but wasn't implemented.
- LLM-based judgment isn't perfectly deterministic. All numbers above
  were confirmed stable across 3 repeated runs, but this is a property
  of local-LLM-based detection worth stating explicitly rather than
  implying certainty a single run can't support.
- The 1.0 detection rate is on this project's own 3-server, 6-vuln test
  bed. It demonstrates the approach works; it is not a claim about
  detection rate on real-world MCP servers at scale.
- mcp-scan (the original planned comparison baseline) was acquired by
  Snyk mid-project and renamed snyk-agent-scan, now requiring a Snyk
  account/API token for real scans. Rather than gate the comparison
  behind a signup, this project built its own transparent regex baseline
  instead — arguably a cleaner comparison anyway, since its exact logic
  is fully inspectable in agents/baseline_regex_scanner.py.

## Running the pipeline

```bash
# Recon only
python3 agents/recon.py servers/clean_server.py

# Full semantic analysis
python3 agents/semantic_analyzer.py servers/tool_poisoning_server.py

# Drift monitor demo (rug pull)
python3 agents/drift_monitor.py baseline servers/rug_pull_server.py
export RUG_PULL=1   # Windows: $env:RUG_PULL="1"
python3 agents/drift_monitor.py check servers/rug_pull_server.py

# Severity-scored report
python3 agents/reporting.py servers/tool_poisoning_server.py --out report.md

# Sandboxed impact demo (synthetic decoy files only)
python3 agents/sandbox_demo.py servers/tool_poisoning_server.py

# Regex baseline (no LLM needed, instant)
python3 agents/baseline_regex_scanner.py servers/tool_poisoning_server.py

# Full benchmark (precision/recall/F1)
python3 agents/benchmark.py --runs 3
```


## Week 5 — The auditor as an MCP server

```
agents/
  auditor_mcp_server.py   # this project, exposed as an MCP server itself
```

Every other agent in this project is an MCP *client* — it connects to
someone else's server and inspects it. `auditor_mcp_server.py` flips
that: it's this project's own detection pipeline, wrapped as an MCP
*server*, exposing two tools:

- `audit_mcp_server(command, args)` — full severity-scored Markdown report
- `quick_verdict(command, args)` — fast one-line-per-tool read

The practical point: this can be added to Claude Desktop's own MCP
config, so before you add some new, unfamiliar MCP server you found
online, you can ask Claude to "use the security auditor to check this
server first" — vetting an untrusted server without your primary
assistant ever touching it directly.

### Try it with our own recon.py (no Ollama needed, just proves the wiring)

```bash
python3 agents/recon.py agents/auditor_mcp_server.py
```
Should show `mcp-security-auditor` exposing exactly two tools,
`audit_mcp_server` and `quick_verdict`.

### Add it to Claude Desktop

In Claude Desktop's config file (find via Settings → Developer → Edit
Config), add:

```json
{
  "mcpServers": {
    "mcp-security-auditor": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-auditor/agents/auditor_mcp_server.py"]
    }
  }
}
```

Restart Claude Desktop, then in a new chat: *"Use the security auditor
to check whether this MCP server is safe before I add it: command=...,
args=..."* — Claude will call `audit_mcp_server` and show you the report
before you commit to trusting the new server. This is the single best
demo moment for a live walkthrough, since it shows the tool being used
the way it's actually meant to be used, not just run from a terminal.
