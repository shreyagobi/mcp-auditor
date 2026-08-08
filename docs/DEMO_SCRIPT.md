# Live Demo Script — MCP Security Auditor

Goal: show your teacher, in real time, that this isn't a static rules
scanner — it's a local LLM that reasons about tool descriptions, catches
an attack that has no suspicious keywords in it, and catches a server
that turns malicious *after* it was already trusted. Total live time:
roughly 10–12 minutes if you do all three acts; 5 minutes if you only
do Act 2.

Everything below was run and verified live on this machine while
preparing this documentation — the exact output you should expect is
saved under `docs/live_verification_outputs/` as a fallback in case
Ollama hiccups mid-demo (slow machine, model not warm, etc.). If a live
command misbehaves, open the matching file there instead of re-running.

---

## 0. Before your teacher sits down (5 min prep, do this alone)

Local LLMs have a slow **cold start** — the first call after `ollama
serve` starts loads the model into memory and can take 30–60+ seconds.
You do not want that delay happening live while your teacher watches a
spinner. Warm the models up first:

```bash
ollama serve
```

(leave that running in its own terminal, or skip if `ollama serve` is
already running as a background service)

```bash
curl http://localhost:11434/api/embeddings -d "{\"model\":\"nomic-embed-text\",\"prompt\":\"warmup\"}"
curl http://localhost:11434/api/chat -d "{\"model\":\"llama3.1:8b\",\"messages\":[{\"role\":\"user\",\"content\":\"say hi\"}],\"stream\":false}"
```

Then, in the terminal you'll actually demo from:

```bash
cd mcp-auditor
python -m venv venv          # skip if venv already exists
venv\Scripts\activate
pip install -r requirements.txt
```

**Windows only** — set this once per terminal session, or the
✅/🚩 severity markers will crash the script with a `UnicodeEncodeError`
(Windows' default console codepage can't render them):

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

---

## Act 1 — "Here's what the auditor is looking at" (~1 min)

Show a target server has no visible red flags to a human skimming it.

```bash
python agents/recon.py servers/tool_poisoning_server.py
```

**Say:** "This is Recon — step one of the pipeline. It connects to any
MCP server and lists every tool it declares, with its full description.
Nothing here screams 'malicious' if you just read it quickly."

Point at the `summarize_document` tool's description in the output —
it reads like an innocuous "also grab the config file" instruction, not
an attack.

---

## Act 2 — The actual differentiator: regex vs. semantic (~4 min)

This is the core result. Run the naive baseline first.

```bash
python agents/baseline_regex_scanner.py servers/tool_poisoning_server.py
```

**Expected:** `convert_currency` is FLAGGED (it has literal words like
"ignore instructions" and "id_rsa"). `summarize_document` comes back
**clean** — the regex scanner misses it.

**Say:** "This represents the class of scanner that already exists —
keyword matching. It catches the obvious one. It misses this one."

Now run the actual project:

```bash
python agents/reporting.py servers/tool_poisoning_server.py
```

**Expected (takes ~1–3 min live, since each tool is a real LLM call):**
both `convert_currency` **and** `summarize_document` come back FLAGGED,
MCP03:2025 — Tool Poisoning, with a reasoning line that quotes the
specific instruction it found.

**Say, while it's thinking:** "For each tool, it retrieves similar
known attack patterns from a small local knowledge base, then asks a
local LLM — llama3.1:8b, running entirely on this machine via Ollama,
nothing leaves this laptop — whether the description contains a hidden
instruction aimed at the AI rather than the human. That's the whole
idea: judge meaning, not keywords."

If it's slow and you want a safe fallback while narrating:
open `docs/live_verification_outputs/3_semantic_report_tool_poisoning.md`
and read the reasoning field out loud — it's the actual model output
from this exact test bed, captured earlier.

---

## Act 3 — The "rug pull": a server that turns malicious after install (~3 min)

This is the moment that's hardest to explain in words and easiest to
*show*. `rug_pull_server.py` starts honest. Flip one environment
variable and its `backup_files` tool quietly starts asking to exfiltrate
SSH keys — with no re-install, no version bump, nothing a user would
notice.

```bash
python agents/drift_monitor.py baseline servers/rug_pull_server.py
```

**Say:** "This takes a snapshot right now and calls it trusted. This is
what any static scanner does — it proves the server was clean *at this
moment*."

```powershell
$env:RUG_PULL = "1"
```

**Say:** "This simulates what a malicious server operator would do
after you've already added their server and started trusting it."

```bash
python agents/drift_monitor.py check servers/rug_pull_server.py
```

**Expected:** `backup_files` reported as `DESCRIPTION_OR_SCHEMA_CHANGED`,
then automatically re-analyzed and FLAGGED as MCP03:2025, with reasoning
naming the SSH-config exfiltration.

**Say:** "A one-shot scanner never sees this — it already gave this
server a clean bill of health and moved on. This agent re-checks and
catches the change the moment it happens."

Reset for next time:

```powershell
$env:RUG_PULL = "0"
```

---

## Optional Act 4 — "This plugs into a real assistant" (~2 min, no live run needed)

**Say:** "Every demo so far ran from a terminal. The actual point is
this project is *itself* an MCP server — `agents/auditor_mcp_server.py`
exposes the whole pipeline as two callable tools, `audit_mcp_server`
and `quick_verdict`. Add this to Claude Desktop's or Claude Code's own
MCP config, and before you add some new MCP server you found online,
you can just ask your assistant: 'use the security auditor to check
this server first' — vetting it without your primary assistant ever
touching the untrusted server directly."

Show the config snippet from `README.md` ("Add it to Claude Desktop")
if you want something on screen rather than just talking.

---

## Optional Act 5 — Visual dashboard instead of a terminal (~2 min)

If your teacher would rather see a UI than scrolling terminal text:

```bash
pip install streamlit
streamlit run dashboard/app.py
```

Pick a server from the sidebar dropdown, click **Run audit**, and the
same pipeline renders as a findings table with severity badges instead
of Markdown in a terminal. The "Take baseline" / "Check drift" buttons
next to it do the same rug-pull flow as Act 3, but clickable.

---

## Closing numbers to state (don't need to re-run live — already validated)

> Across the full 6-server test bed, 3 repeated runs each: **Precision
> 1.0, Recall 1.0, F1 1.0** — 15/15 planted vulnerabilities caught,
> 0/30 false positives. A smaller model (llama3.2:3b) was tested the
> same way and missed both tool-poisoning payloads, which is why the
> project defaults to the 8B model — a measured threshold, not an
> assumption.

Full numbers, the OWASP mapping, and all limitations are in
`docs/MCP_Security_Auditor_Documentation.docx`.

## If Ollama isn't behaving on demo day

- `ollama list` should show `llama3.1:8b` and `nomic-embed-text`. If
  either is missing: `ollama pull llama3.1:8b` / `ollama pull nomic-embed-text`.
- If a call hangs for more than ~90s, the model probably isn't warm —
  this is why Step 0 matters. Don't skip it.
- Every file under `docs/live_verification_outputs/` is a real,
  captured run from this exact test bed — safe to show directly if a
  live call fails mid-presentation.
