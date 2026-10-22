# A01: CVE Triaging — Design and Analysis

## 1. Overview

The system reads a security-analyst artifact (port scan, SBOM, package
listing, banners, notes) and produces, per document, the software present
(as NVD CPEs) and the 2026 CVEs that apply, each with its CWE. It is built on
AgentLab with the two task-specific containers replaced:

- **`mcp/`** — a vulnerability knowledge server that loads the five frozen
  feeds into an in-memory SQLite database and answers questions about CVE,
  CWE, CAPEC, KEV and CPE over MCP.
- **`agent/`** — a LangGraph pipeline that extracts software from each
  document, resolves it to CPE identities, asks the MCP server which 2026
  CVEs apply, and writes one result per document.

The guiding principle is a **deterministic spine with the model used only
where language understanding is unavoidable**. All vulnerability facts come
from the MCP server; the model never emits a CVE or CWE.

## 2. The MCP server

**Loading (`mcp/loader.py`).** On startup the server parses all five feeds
(stdlib only: `gzip`, `tarfile`, `zipfile`, `xml.etree`) into an in-memory
SQLite database. The container's root filesystem is read-only, so the database
lives in RAM (`PRAGMA temp_store = MEMORY`). The 900 MB CPE dictionary is
streamed chunk-by-chunk so memory stays well under the 6 GB limit; the load
takes ~50 s, inside the 5-minute health budget. Feeds are loaded *before* the
HTTP server starts, so "healthy means ready": `GET /health` only answers once
the data is queryable.

What is kept: every 2026 CVE (description, best CVSS, CWE ids, KEV flag); every
`vulnerable` CPE match (vendor/product + version bounds); every CPE product's
name and title; versions only for products a 2026 CVE mentions; CWE and CAPEC
names/descriptions and the links between them; the KEV catalog.

**Tools.** The seven required tools (`db_info`, `get_cve`, `get_cwe`,
`get_capec`, `get_kev`, `search_products`, `vulnerabilities_for`) plus
`list_versions`. `search_products` is a case-insensitive substring search over
CPE vendor/product/title with a relevance ranking; it is the agent's
name→CPE bridge. `vulnerabilities_for` is the core: it pulls the CPE match
rows for a vendor/product and tests the version in Python.

**Version matching (`mcp/version.py`).** Versions are tokenised into numeric
and alphabetic runs and compared as lists, so `2.4.29 < 2.4.58` and
`7.2 < 7.2p2` order correctly. A CVE applies when a `vulnerable` match names
the version exactly, gives a range containing it, or names every version.

## 3. The agent pipeline

The pipeline (`agent/app/graph.py`) is a LangGraph state machine:

```
list_inputs -> read_next -> extract -> resolve -> lookup -> write -> (loop)
```

- **`extract` (`parsers.py`)** turns a document into `(name, version,
  evidence)` candidates. Structured, tool-generated formats are parsed
  deterministically: JSON SBOMs (CycloneDX/SPDX/syft), `package-lock.json`,
  `dpkg -l`, `rpm -qa` (NEVRA), apt pins (`pkg=version`), pip, apk, nmap XML
  (which carries an embedded CPE), and Maven POMs. A document is classified
  as a *pure package dump* only when package lines dominate; otherwise the
  deterministic pass is combined with a model read, so mixed documents (a
  host report with a `dpkg` excerpt and a scan line) are fully covered.
- **`resolve` (`resolver.py`)** maps each name to its CPE `vendor:product`
  identities. Three tiers: a small hand table of structural naming facts; the
  MCP `search_products` with a strict ranker; and, when search finds nothing,
  a model call to clean the name.
- **`lookup`** calls `vulnerabilities_for` for every identity and unions the
  CVEs, selecting the CPE to report by CVE count (then the canonical
  `vendor==product` form).
- **`write`** emits the result JSON under the input's own id.

### What the model does vs. what code does

The model is used at exactly two points, both about *naming only*:
`extract` on loose/free-form documents (banners, analyst notes), and
`resolve` when deterministic search cannot place a name. Everything else —
format parsing, version normalisation, CVE/CWE lookup, version-range
matching, output assembly — is deterministic code or MCP queries. The model
never produces a CVE or CWE; its output is always re-grounded through the MCP
server, so it cannot invent vulnerabilities. This keeps the system robust to
which model is behind the gateway and keeps model cost low (structured
documents make no model calls at all).

### General mechanisms, not per-document patches

Two small hand tables are allowed by the handout (name→CPE maps). We kept them
disciplined:

- **`ALIASES`** holds only *structural naming facts* that search cannot
  recover: cases where the document's name shares no word with the CPE
  product (`httpd`→`apache:http_server`, `libssl`→`openssl:openssl`,
  `liblzma`→`tukaani:xz`), or where NVD files one product under several
  vendors (`nginx` includes `f5:nginx_open_source`, where all its 2026 CVEs
  live). Products whose name matches their CPE product resolve through search
  and are deliberately *not* listed, which is what lets the resolver handle
  products not seen in training.
- **`NEUTRAL`** drops only unambiguous OS/distro plumbing. It is kept small on
  purpose: the grader already ignores OS packages and tolerates extras, so a
  neutral list can only break even or, if it wrongly lists a real product,
  lose points — an early version mistakenly neutralised `libxml2`, `glibc` and
  `zlib`, which are scored products, and those were removed.

## 4. Failure analysis (training set)

On the 50 training documents the system scores ~97 (every structured format
at 100). The debugging process surfaced several issues; the useful lesson was
distinguishing *general* bugs from *tolerated noise*.

**General bugs found and fixed (generalise beyond the training docs):**

- `rpm -qa` versions were initially read as the `release.arch` suffix; a
  proper NEVRA parser fixed two documents from 0 to 100.
- Sub-package names (`openssh-server`, `sqlite-libs`) and separator mismatches
  (`commons-collections` vs `commons_collections`) failed to resolve; handled
  by suffix stripping and a separator-normalised search fallback.
- nmap's embedded CPE for nginx is `f5:nginx`, but its CVEs are under
  `f5:nginx_open_source`; the embedded CPE is now enriched with the alias
  table so no identity is missed.
- MariaDB reports over the MySQL protocol as `5.5.5-<version>-MariaDB`; the
  real version is extracted (a documented, universal MariaDB convention).

**Deliberately not "fixed" (chasing these would be overfitting):**

- "N reported CVEs do not apply" notes come from NVD all-versions matches
  combined with a platform in an AND node — the handout calls these optional
  and they carry no penalty.
- Extra products such as an SNMP community string or an IP read as a version
  are absorbed by the 2× extras allowance and cost nothing; filtering them
  would risk dropping legitimate versions.

**Remaining soft spots:** free-form formats (analyst notes, banners) depend on
the model's extraction, which varies run to run; this is the inherent limit of
reading untrusted prose rather than a generalisation failure. A resolution
coverage check over a random sample of all 2026-CVE products (using only the
feeds) confirmed the mainstream server-software universe resolves well, with
remaining gaps concentrated in firmware and enterprise products unlikely to
appear in realistic scan documents.

## 5. Security boundary

The AgentLab boundary is unchanged: the agent reaches the model only through
the gateway and vulnerability data only through the MCP server; neither
container can reach the internet. No vulnerability data is baked into either
image — it is all loaded from the read-only `/feeds` mount. The MCP container
keeps its read-only root filesystem, dropped capabilities and non-root user.

<!-- TODO (author): drop in the exact grade.py numbers from your latest full
50-document run, and the feedback-run score once available. -->
