# AI usage

I used an AI coding assistant (Kiro, running on Anthropic Claude models)
throughout this assignment.

**What I used it for**
- Designing the architecture: the deterministic-spine-plus-model agent, and
  the vulnerability MCP server (loading the feeds into in-memory SQLite,
  the tool set, and the version-range matching).
- Writing most of the code in `agent/app/` (`parsers.py`, `resolver.py`,
  `llm.py`, `graph.py`) and `mcp/` (`server.py`, `loader.py`, `version.py`).
- Iterating on resolution: moving from a hand-written alias table toward a
  data-driven, multi-identity resolver (CVE-aware `search_products`, the
  model-judged `same_product` grouping, title matching, and the SBOM Package
  URL hint), and adding the extraction and junk-version fixes.
- Debugging against the training grader: diagnosing per-document misses and
  deciding, case by case, whether a fix was a general mechanism or an
  overfit patch.
- Drafting this file and `REPORT.md`.

**How I checked its output**
- Ran the course grader (`grader/grade.py`) on the 50 training documents and
  the MCP conformance probe (`grader/mcp_probe.py`) against the server,
  across iterations, and read the per-document misses rather than trusting a
  summary score.
- Verified the heaviest logic (feed loading, version matching, name
  resolution) directly against the frozen feeds rather than trusting the
  model's description of it — including a resolution coverage check over a
  random sample of all 2026-CVE products and before/after checks of the
  multi-identity resolution on the real CPE data.
- Reviewed each change for generalisation: confirmed the remaining hand
  tables encode real naming facts (not training-document values), that the
  OS-package filter never drops a scored product, and that fixes did not
  hard-code answers for specific training documents.
