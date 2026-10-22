# A01 CVE Triaging — Project Context (session handoff)

This is a working-context document to transfer state into a new session. It
covers the assignment, the design, every source file, the design philosophy,
the testing history, known issues, submission mechanics, and current state.

---

## 1. The assignment

Build an agentic system (on top of **AgentLab**) that reads a security-analyst
artifact — a port scan, SBOM, package listing, banners, or analyst notes — and
produces, per input document:

1. **What software is present** — product + version, as an NVD CPE.
2. **Which 2026 CVEs apply** (`CVE-2026-*`), each with the **CWE** behind it.

We replace AgentLab's two task containers:

- **`mcp/`** → a **vulnerability knowledge server** (CVE/CWE/CAPEC/KEV/CPE from
  the frozen feeds, behind MCP tools).
- **`agent/`** → the **triage pipeline** (reads `/work/input/items/`, writes
  `/work/output/items/<id>.json`).

Everything else in AgentLab stays, including the no-internet boundary: the
agent reaches the model only via the gateway, and vuln data only via our MCP
server.

**Scope:** only 2026 CVEs (~70k). The CPE dictionary is huge (1.8M entries);
only ~6k products have a 2026 CVE.

**Scoring (per document, averaged):** products 0.40, cves 0.40, cwe 0.20.
Extras are free up to 2× the real product count, then scaled down. OS/base
packages and version-less software are ignored by the grader "whether you
report them or not." Reference solution scores ~98–100; parsers alone ~65–69.

**Grade:** effectiveness on the private half (60), MCP conformance probe (10),
MCP server design (15, AI-assessed), write-up (15, AI-assessed).

---

## 2. Data: the feeds (`feeds/`, frozen snapshot 2026-10-12)

| File | What we use |
|---|---|
| `nvdcve-2.0-2026.json.gz` | 2026 CVEs: description, CVSS, CWE ids (`weaknesses[]`), and **CPE applicability** (`configurations[].nodes[].cpeMatch[]`) |
| `nvdcpe-2.0.tar.gz` | CPE dictionary (chunked JSON): official vendor/product names + titles |
| `cwec_latest.xml.zip` | CWE 4.20: names, descriptions, related CAPEC |
| `capec_latest.xml` | CAPEC 3.9: attack patterns, related CWEs |
| `known_exploited_vulnerabilities.json` | CISA KEV catalog |

The grader mounts its **own copy** of these at `/feeds`; our `feeds/` is
ignored at grading. No vuln data may be baked into the images.

Training data: `datasets/train/items/` (50 docs) + `datasets/train/expected.json`
(answer key). This is the only labeled data we can test against locally.

---

## 3. Architecture

**Core principle:** a **deterministic spine** owns control flow and all
vulnerability lookups; the **model is used only for naming** (reading messy
documents and disambiguating names). The model **never emits a CVE or CWE** —
all vuln facts come from the MCP server, and any model output is re-grounded
through it.

### Flow (per document)
```
extract (name+version)  ->  resolve (name -> CPE vendor:product aliases)
                        ->  lookup (vendor:product:version -> CVEs+CWEs, via MCP)
                        ->  write
```
- **extract**: raw strings from the doc. Deterministic parsers for structured
  formats; model for loose/free-form text.
- **resolve**: name → set of CPE `vendor:product` "aliases". One product can
  have several NVD identities (e.g. nginx).
- **lookup**: query MCP `vulnerabilities_for` for each alias, union CVEs.
- **write**: assemble output JSON under the input's own id.

---

## 4. Source files

### MCP server (`mcp/`)
- **`loader.py`** — parses all 5 feeds into an **in-memory SQLite** DB (root FS
  is read-only; `PRAGMA temp_store=MEMORY`). Streams the 900 MB CPE tarball
  chunk-by-chunk. Loads in ~50 s. Tables: `cve`, `cve_cwe`, `cve_match`
  (vendor/product + version bounds), `cpe_product`, `cpe_version`, `cwe`,
  `cwe_capec`, `capec`, `capec_cwe`, `kev`, `meta`.
- **`version.py`** — version comparison for CPE applicability. Tokenises into
  numeric/alpha runs and compares as lists (`2.4.29 < 2.4.58`, `7.2 < 7.2p2`).
  `matches(version, exact, v_start, start_incl, v_end, end_incl)`.
- **`server.py`** — MCP server (Streamable HTTP, port 8000, `/mcp`). Loads feeds
  **before** serving so `/health` = ready. Tools: `db_info`, `get_cve`,
  `get_cwe`, `get_capec`, `get_kev`, `search_products`, `vulnerabilities_for`
  (the 7 required) + `list_versions`. `search_products` = substring search over
  vendor/product/title with ranking.
- **`Dockerfile`** — `python:3.13-slim`, installs only `mcp>=2.2,<3` (feed
  parsing is stdlib). `python` on PATH for the healthcheck. Read-only FS,
  cap-drop, non-root (from compose).

### Agent (`agent/app/`)
- **`graph.py`** — LangGraph state machine. Nodes: `list_inputs`, `read_next`,
  `extract`, `resolve`, `lookup`, `write`. `extract` runs the model on
  non-structured docs; `resolve` uses alias table → MCP search → model
  `suggest_name` fallback; when a parser supplies an embedded CPE (`c["vp"]`,
  from nmap), it is **enriched with the alias table** (critical — see nginx
  below). `lookup` unions CVEs across aliases and picks the reported CPE by
  CVE count then `vendor==product`.
- **`parsers.py`** — deterministic extraction. `detect()` (json/xml/text) +
  per-format parsers: JSON SBOMs (CycloneDX/SPDX/syft), npm lock, `dpkg -l`,
  `rpm -qa` (NEVRA via rpartition + split at first `-<digit>`), apt pins
  (`pkg=version`, dotted digit-led value only), pip (`==`), apk, nmap XML
  (`<service>` + embedded `<cpe>`), Maven POM (`<dependencies>`, `${property}`
  resolution, skips test scope). `normalize_version()` strips epoch,
  `.dfsg`, distro suffixes, and the MariaDB `5.5.5-<v>-MariaDB` protocol
  prefix. `_SO_FILE` extracts `lib<name>.so.<version>` from fs listings.
  `extract()` returns `(fmt, candidates, structured)`; `structured=True`
  (skip model) only when package lines are ≥50% of content (so mixed docs
  still run the model).
- **`resolver.py`** — `ALIASES` (hand table of structural naming facts),
  `NEUTRAL` (OS-package filter), `clean_name` (strip sub-package suffixes
  like `-server`/`-libs`), `is_neutral`, `rank_pick` (strict matching: exact,
  `vendor product` two-word, normalized-equal, shared-token; rejects
  title-only/junk matches; returns all strong matches so CVE-count selection
  picks the right identity).
- **`llm.py`** — the two model calls: `extract_products(text)` (messy doc →
  JSON list of name/version) and `suggest_name(raw)` (clean an unresolvable
  name). Parses first JSON value from the reply; best-effort (a refusal/parse
  failure falls back to deterministic results). Uses the gateway-only
  `ChatOpenAI`, temperature 0.
- **`clients.py`** — the two MCP connections (local stdio I/O server; remote
  HTTP vuln server). `PROCESSORS` tuple was changed to
  `("search_products", "vulnerabilities_for")` (the startup validation list).
- **`io_server.py`, `config.py`, `run.py`, `tracing.py`, `kb.py`** — AgentLab
  platform, reused. (`classify.py`, `specialists.py` were the demo modules and
  were **deleted**.)

---

## 5. Design philosophy: general vs. overfit (IMPORTANT)

The owner is (rightly) vigilant about overfitting to the training docs. The
standing rule for every fix: **address the real underlying mechanism, make it
generalize, and do not add a per-document/per-product patch just to pass a
test. Also do not over-correct in the other direction — leave tolerated noise
alone.**

### `ALIASES` table — audited, all entries justified
Holds ONLY structural naming facts search cannot recover:
- name shares no word with CPE product: `httpd`→`apache:http_server`,
  `libssl*`→`openssl:openssl`, `liblzma`→`tukaani:xz`, `libcurl`→`curl`,
  `node`→`nodejs:node.js`, `microsoft-iis`/`iis`→`microsoft:internet_information_services`,
  `mysqld`/`mysql`→`oracle:mysql`, `python3-django`→`djangoproject:django`.
- NVD multi-vendor identity: `nginx`→ includes `f5:nginx_open_source`
  (**all 18 nginx 2026 CVEs live there**; search for "nginx" never returns it).
Products whose name ≈ CPE product (redis, grafana, mongodb, …) are NOT listed —
search + rank + CVE-count selection handles them, which is what generalizes to
unseen products. Verified: removing each entry either breaks resolution or
loses CVEs.

### `NEUTRAL` list — a repeated overfit hazard, now minimal
This caused the only real overfit bug twice: real products (`libxml2`,
`glibc`, `zlib`) were wrongly listed and got dropped. Key insight: the grader
**already ignores OS packages and tolerates extras up to 2×**, so a neutral
list can only break even or hurt. It is now trimmed to unambiguous OS/distro
plumbing only, and audited so **no entry is ever a scored product**.

### What is deliberately NOT fixed (tolerated noise, 0 points)
- "N reported CVEs do not apply": NVD all-versions matches AND-ed with a
  platform; handout calls these optional, no penalty.
- Extra products from IP-as-version (`public:10.0.0.1`), SNMP community
  strings, `ssl_client 1.34.1`→openssl: all within the 2× allowance. Filtering
  would risk dropping legitimate versions → overfitting.

---

## 6. Testing

- **Local run (see `TESTING.md`):** `make up MODE=agent`, then the MCP probe,
  then `AGENT_MODEL=mock-model make run` (free) or `AGENT_MODEL=external make
  run` (real Claude via `.env` `EXTERNAL_*` lines), then
  `python3 grader/grade.py --expected datasets/train/expected.json --outputs
  output/items -v`.
- **Offline verification harness (used heavily):** load the feeds + import the
  agent modules in a `/tmp` script to test extraction/resolution/version
  matching against the real feeds **without Docker or the model** — this
  validated all deterministic logic.
- **Resolution coverage check (unbiased generalization test):** sample random
  products that actually have 2026 CVEs and check whether our resolver recovers
  their CVE-bearing identity. Found ~86% recovery; remaining gaps are mostly
  firmware/enterprise products unlikely in realistic scan docs (plus a narrow
  scoped-npm weakness). This is the best *free* way to find resolution bugs we
  didn't think of; it does NOT test extraction or 0-CVE identity matching.

### Results history (training 50)
Iterations improved the score from an initial ~73 (on docs 1–10) to **~96.97
on the full 50**. Every structured/deterministic format scores **100** across
all 50 (cyclonedx, dpkg, rpm, spdx, syft*, dockerfile, fs-listing, host-report,
html, http-headers, pip, ps-aux, version-commands, whatweb, windows-inventory,
nmap-normal, maven-pom, apk). Soft spots:
- **analyst-notes ~79, banners ~89** — model-extraction variance on free-form
  prose (inherent, not overfitting; varies run to run).
- **nmap-xml 88.66** — fixed by the nginx-embedded-CPE + MariaDB changes (doc-048
  verified to 100 offline afterward).
- **npm-lock 90 (express→openjsf), syft 96 (struts2-core→apache:struts),
  nmap-grepable 96 (IIS)** — 0-CVE / SBOM-artifact-name resolution edge cases;
  deliberately not patched (would be per-product overfitting).

---

## 7. Submission & feedback mechanics

- The grader **builds `agent/Dockerfile` and `mcp/Dockerfile`** and runs them in
  the course's own AgentLab. Our `compose.yaml`/`gateway/`/Makefile are **not**
  used for grading (but `compose.yaml` must exist for preflight).
- **Required files:** `agent/Dockerfile`, `mcp/Dockerfile`, `REPORT.md` (or
  `.pdf`), `submission.toml` (`members = ["Tyler-W0ng"]`), `AI_USAGE.md`,
  `compose.yaml`. `feeds/` ignored.
- **Preflight** (`python3 .cs279/preflight.py`) must be green. It checks files
  exist, `members` is set, imports resolve, Dockerfile COPY sources exist, and
  warns on `TODO` in `AI_USAGE.md`. (Do NOT put files in `.cs279/`.)
- **Feedback runs:** push a `feedback-*` tag. Scores the **public half of the
  eval set** (50 unseen docs — DIFFERENT from training). **Only 3 total** for
  the whole assignment; graded once per tag name; scores are indicative. The
  final grade uses the **private half** (never shown).
- Model = Claude Sonnet 5.5, $3 budget, 60 min, 4 concurrent. Local dev used a
  different Sonnet; low model-sensitivity by design, but measure on 5.5 before
  final submit.

---

## 8. Current state & next steps

**Committed (origin/main, "6th iteration" d2f2c1a):** all code fixes — RPM
NEVRA, sub-package stripping, separator fallback, strict rank_pick, canonical
CVE-count selection, apt pins, `.dfsg`, MariaDB version, nginx embedded-CPE
enrichment, trimmed NEUTRAL.

**Uncommitted (just written this session):**
- `submission.toml` → `members = ["Tyler-W0ng"]`
- `REPORT.md` → full draft (has one author-note to insert final grade numbers)
- `AI_USAGE.md` → disclosure (TODO removed)
- `PROJECT_CONTEXT.md` → this file

Preflight is **green**.

**Next steps:**
1. `git add` the submission files (git commit -a skips new files), commit, push.
2. Verify on github.com: latest commit on `main`, green preflight ✓.
3. Confirm `docker build agent` and `docker build mcp` succeed.
4. Review `REPORT.md` / `AI_USAGE.md` so they match reality (your claims).
5. Spend **one** `feedback-1` tag to get a read on unseen docs; keep 2 in
   reserve.
6. Optional improvements (debatable value, weigh overfitting): tighten the
   `llm_extract` prompt to improve recall on analyst-notes/banners (a general
   change); investigate scoped-npm (`@scope/name`) resolution.

**Repo meta:** git identity is set locally to `Tyler-W0ng` /
`tyler_wong@ucsb.edu`. GitHub auth is via a Personal Access Token over HTTPS
(password prompt = paste the token).

**Key gotchas learned:**
- `clients.py` `PROCESSORS` must list tools the MCP server actually offers or
  the agent refuses to start.
- The MCP server must load feeds BEFORE serving (health = ready).
- `NEUTRAL` must never contain a real product (audit it against the training
  truth products).
- Embedded CPEs (nmap) must be enriched with the alias table or multi-identity
  products (nginx) lose CVEs.
- Don't put dev scripts in `.cs279/` (course tools dir).
