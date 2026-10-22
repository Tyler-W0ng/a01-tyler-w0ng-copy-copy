# AI usage

I used an AI coding assistant (Kiro, Claude-based) throughout this assignment.

**What I used it for**
- Designing the architecture: the deterministic-spine-plus-model agent, and
  the vulnerability MCP server (loading the feeds into in-memory SQLite,
  the tool set, and the version-range matching).
- Writing most of the code in `agent/app/` (`parsers.py`, `resolver.py`,
  `llm.py`, `graph.py`) and `mcp/` (`server.py`, `loader.py`, `version.py`).
- Debugging against the training grader: diagnosing per-document misses and
  deciding, case by case, whether a fix was a general mechanism or an
  overfit patch.
- Drafting this file and `REPORT.md`.

**How I checked its output**
- Ran the course grader (`grader/grade.py`) on the 50 training documents and
  the MCP conformance probe (`grader/mcp_probe.py`) against the server.
- Verified the heaviest logic (feed loading, version matching, name
  resolution) directly against the frozen feeds rather than trusting the
  model's description of it.
- Reviewed each change for generalisation: confirmed hand tables encode real
  naming facts (not training-document values) and that the OS-package filter
  never drops a scored product.

<!-- Author: edit the above to reflect exactly which tools/models you used and
how you verified the results, per the course submission guide. -->
