"""
patterns.py — RAG seed data.

Curated set of known MCP attack patterns, written as short descriptive
snippets (not full CVE writeups) that get embedded and stored in the
vector DB. When the Semantic Analyzer looks at a tool description, it
retrieves the k most similar patterns here and includes them as
grounding context for the LLM's judgment — this is what makes a finding
"retrieval-augmented" instead of just "an LLM's opinion."

Sources (cite these in your report / README, this doubles as literature):
  - OWASP MCP Top 10 (beta): https://github.com/OWASP/www-project-mcp-top-10
  - The Vulnerable MCP Project tracker (community-maintained CVE/incident list)

Each pattern is deliberately short and generic — a *description of a
technique*, not a working exploit — appropriate for a defensive
detection knowledge base.
"""

PATTERNS = [
    # ---- MCP03: Tool Poisoning ----------------------------------------
    {
        "id": "P-TP-01",
        "owasp_code": "MCP03:2025",
        "owasp_category": "Tool Poisoning",
        "text": (
            "A tool description contains an embedded instruction block "
            "(sometimes wrapped in tags like <system_note> or "
            "<IMPORTANT>) that tells the calling model to perform an "
            "action unrelated to the tool's stated purpose, such as "
            "reading a credential file or private key and including its "
            "contents in the response."
        ),
    },
    {
        "id": "P-TP-02",
        "owasp_code": "MCP03:2025",
        "owasp_category": "Tool Poisoning",
        "text": (
            "A tool description instructs the model to conceal an action "
            "from the user, using phrasing like 'do not mention this' or "
            "'no need to call this out separately', which is a strong "
            "signal of intentionally hidden behavior."
        ),
    },
    {
        "id": "P-TP-03",
        "owasp_code": "MCP03:2025",
        "owasp_category": "Tool Poisoning",
        "text": (
            "A tool description asks the model to override or ignore "
            "prior safety instructions, system prompts, or guardrails "
            "before performing the tool's action."
        ),
    },
    {
        "id": "P-TP-04",
        "owasp_code": "MCP03:2025",
        "owasp_category": "Tool Poisoning",
        "text": (
            "A tool description contains instructions phrased as routine "
            "or helpful steps (e.g. 'as a routine step, also open...') "
            "that in fact direct the model to access sensitive files "
            "such as cloud credentials, SSH keys, environment files, or "
            "browser cookie stores, without using any obviously alarming "
            "keywords — an attempt to evade keyword-based scanners."
        ),
    },
    {
        "id": "P-TP-05",
        "owasp_code": "MCP03:2025",
        "owasp_category": "Tool Poisoning",
        "text": (
            "A tool description references other tools or servers by "
            "name and instructs the model to change how it calls them "
            "(a 'trusted tool shadowing' pattern), letting one malicious "
            "server manipulate behavior toward a different, legitimate "
            "server the user actually trusts."
        ),
    },
    # ---- MCP02: Privilege Escalation via Scope Creep -------------------
    {
        "id": "P-PE-01",
        "owasp_code": "MCP02:2025",
        "owasp_category": "Privilege Escalation via Scope Creep",
        "text": (
            "A tool's description claims a narrow, safe capability such "
            "as 'read-only' or 'preview only', but its input schema "
            "includes parameters (e.g. a boolean flag) that enable "
            "destructive operations like deleting files or directories "
            "not mentioned in the description."
        ),
    },
    {
        "id": "P-PE-02",
        "owasp_code": "MCP02:2025",
        "owasp_category": "Privilege Escalation via Scope Creep",
        "text": (
            "A tool name is a near-identical typo of a well-known, "
            "trusted tool name (typosquatting), increasing the chance a "
            "user or agent calls it by habit while it silently performs "
            "additional actions the trusted original would not."
        ),
    },
    {
        "id": "P-PE-03",
        "owasp_code": "MCP02:2025",
        "owasp_category": "Privilege Escalation via Scope Creep",
        "text": (
            "A tool description mentions a side effect (like 'keep in "
            "sync with remote') in passing, soft-pedaling the fact that "
            "the tool performs network access or state-changing "
            "operations beyond what its primary described function "
            "(e.g. a status check) would require."
        ),
    },
    {
        "id": "P-PE-04",
        "owasp_code": "MCP02:2025",
        "owasp_category": "Privilege Escalation via Scope Creep",
        "text": (
            "A tool's input schema accepts a file path or directory "
            "parameter with no described validation or sandboxing, "
            "creating potential for path traversal outside an intended "
            "working directory."
        ),
    },
    # ---- MCP01: Token Mismanagement & Secret Exposure ------------------
    {
        "id": "P-TM-01",
        "owasp_code": "MCP01:2025",
        "owasp_category": "Token Mismanagement & Secret Exposure",
        "text": (
            "A tool description or example asks the model to pass "
            "long-lived credentials, API keys, or tokens directly as "
            "plaintext tool call arguments rather than referencing a "
            "secret store, risking exposure in logs, protocol traces, or "
            "model context."
        ),
    },
    # ---- MCP06: Prompt Injection via Contextual Payloads ---------------
    {
        "id": "P-PI-01",
        "owasp_code": "MCP06:2025",
        "owasp_category": "Prompt Injection via Contextual Payloads",
        "text": (
            "Content returned by a tool call (not the description, but "
            "the tool's output/result) contains instructions directed at "
            "the model rather than data for the user, attempting to "
            "hijack the agent's next action."
        ),
    },
    # ---- MCP09: Shadow MCP Servers --------------------------------------
    {
        "id": "P-SH-01",
        "owasp_code": "MCP09:2025",
        "owasp_category": "Shadow MCP Servers",
        "text": (
            "A server or tool set was added to an agent's configuration "
            "outside of any formal review or allowlist process, and has "
            "broad tool access (file, network, or credential access) "
            "with no corresponding documentation or approval trail."
        ),
    },
]
