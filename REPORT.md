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
from the MCP server; the model never emits a CVE or CWE, and anything it does
produce (a product name) is re-grounded through the server before it can
affect the answer. This keeps the system robust to which model is behind the
gateway and keeps cost low — structured documents make no model calls at all.

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
names/descriptions and the links between them; the KEV catalog. One derived
table, `cve_product` (the distinct vendor/product pairs that carry a 2026 CVE,
~6 k rows), lets the search tool cheaply tell a CVE-bearing name from a bare
dictionary entry.

**Tools.** The seven required tools (`db_info`, `get_cve`, `get_cwe`,
`get_capec`, `get_kev`, `search_products`, `vulnerabilities_for`) plus
`list_versions` and `resolve_name`. Three design choices make the server, not
the agent, own the *name→CPE* problem — the agent's hardest — so a model could
call it directly:

- **`resolve_name` (`mcp/resolve.py`)** maps a package/banner name to CPE
  identities: it strips sub-package suffixes (`openssh-server`→`openssh`),
  applies a small table of *structural* naming facts (`httpd`→
  `apache:http_server`, `libssl`→`openssl:openssl`, `liblzma`→`tukaani:xz`),
  searches, and ranks by confidence. A match on only a **generic** word
  (`engine`, `zip`, `server`, …) is rejected unless the vendor also agrees, so
  "Zend Engine" no longer resolves to `docker:engine`, nor "7-Zip" to
  `info-zip:zip`. It returns the best product's identities, the table seed, and
  same-family `variants` for the agent to adjudicate, each flagged `has_cves`.
  This holds only naming facts, never vulnerability data.
- **`search_products`** ranks names that carry a 2026 CVE first and never drops
  them (`has_cves` on each), because NVD files one product's CVEs under several
  slugs: a search for `mysql` must surface `oracle:mysql_server`, not only
  `oracle:mysql`, or the caller can never find where the CVEs live. It is
  capped at the 20 best candidates so the list stays small for a model to read.
- **`vulnerabilities_for`** is the core lookup: it **normalises the version**
  (epoch, distro suffix, MariaDB marker — `mcp/version.py`) so any caller may
  pass `1:7.6p1-4ubuntu0.7` directly, then tests each CPE match row in Python.
  It returns a **`known`** flag (is this vendor:product in the data at all), so
  a caller can tell a misresolution from a genuine product with no 2026 CVEs —
  both of which otherwise return an empty `cves` list.

**Version matching (`mcp/version.py`).** Versions are tokenised into numeric
and alphabetic runs and compared as lists, so `2.4.29 < 2.4.58` and
`7.2 < 7.2p2` order correctly. A CVE applies when a `vulnerable` match names
the version exactly, gives a range containing it, or names every version —
where "every version" is only NVD's `*`; a `-` (N/A) match with no range is
dropped at load time rather than treated as all-versions (which over-reported).

## 3. The agent pipeline

The pipeline (`agent/app/graph.py`) is a LangGraph state machine:

```
list_inputs -> read_next -> extract -> resolve -> lookup -> write -> (loop)
```

**`extract` (`parsers.py`)** turns a document into `(name, version, evidence)`
candidates. Structured, tool-generated formats are parsed deterministically:
JSON SBOMs (CycloneDX/SPDX/syft), `package-lock.json`, `dpkg -l`, `rpm -qa`
(NEVRA), apt pins (`pkg=version`), pip, apk, nmap XML (which carries an
embedded CPE), and Maven POMs. A document is treated as a *pure package dump*
only when package lines dominate; otherwise the deterministic pass is combined
with a model read, so mixed documents (a host report with a `dpkg` excerpt and
a scan line) are fully covered. Several robustness rules live here: candidate
versions that are not version-shaped are rejected (an internal IP read as a
version, or a bare word like `Ubuntu`); prose words that precede a number in
tool-summary lines are dropped, so `Nmap done … scanned in 346.53 seconds`
does not become a product and `Redis key-value store 5.0.7` is not read as
"store"; a filesystem path segment like `Jinja2-3.1.2.dist-info` is parsed to
`(jinja2, 3.1.2)`; and for SBOM entries the Package URL is read so a Java
artifact's build name (`struts2-core`) falls back to its project
(`org.apache.struts` → "apache struts").

**`resolve` (`neutral.py` + the server + the model)** maps each name to the
set of CPE `vendor:product` identities under which NVD may file its CVEs. The
heavy lifting is the server's `resolve_name`; the agent only orchestrates:

1. Drop OS base packages (a small, audited `NEUTRAL` list — the only naming
   logic left in the agent — including the OS kernel itself, which otherwise
   resolves to `linux:linux_kernel` and dumps ~1000 CVEs).
2. Trust a parser-supplied CPE (nmap) when present, enriched with the server's
   table seed (nmap reports nginx as `f5:nginx`, but its CVEs live under
   `f5:nginx_open_source`).
3. Call **`resolve_name`**, which cleans the name, applies the alias seed,
   searches and ranks by confidence (exact/normalised name, a shared
   distinctive word, or — for a multi-word name — a **title** match so "GNU C
   Library" reaches `gnu:glibc`), rejecting generic-word look-alikes.
4. **Adjudicate the product's family.** `resolve_name` returns same-*base*
   variants (`mysql`→`mysql_server`, `nginx`→`nginx_open_source`); the model
   decides which are the *same* software (keep `mysql_server`) and which merely
   share a word (drop `mysql_cluster`, `mysql_workbench`).
5. If nothing resolves, fall back to the model to canonicalise the name — the
   SBOM purl hint first, then `suggest_name` — and call `resolve_name` again.

**`lookup`** calls `vulnerabilities_for` for every identity and unions the
CVEs, then selects the CPE to report by CVE count, then a curated (table/
embedded) identity, then the canonical `vendor==product` form.

**`write`** emits the result JSON under the input's own id.

### What the model does vs. what code does

The model is used at exactly **three** points, all about *naming only*:
`extract` on loose/free-form documents (banners, analyst notes); `resolve`'s
`same_product` grouping (which of several real CPE identities denote one
product); and `resolve`'s `suggest_name` fallback (clean a name search cannot
place). In all three the model may only choose or rephrase among things that
already exist — in `same_product` it selects from CPE identities the server
returned and can keep or drop a real one but never invent one. A product the
model extracts is re-grounded twice: its name must resolve through
`resolve_name`, and its *version* must actually appear in the source text, so a
version the model invents from a process listing is discarded. Everything else
— format parsing, version normalisation, CVE/CWE lookup, version-range
matching, identity union, output assembly — is deterministic code or MCP
queries. Because every model output is re-grounded through the server, the
model cannot produce a vulnerability, and the system behaves consistently
across models.

### General mechanisms, not per-document patches

The central design decision is to resolve a product's CPE identities **from
the data**, not from a hand table. NVD files one product under several names;
rather than memorise them, the server surfaces the CVE-bearing siblings and
the model judges which belong to the same product using the CPE titles. This
is what recovers, for example, all of MySQL 8.0.32's CVEs (which live mostly
under `oracle:mysql_server`, a different slug from the one a document names)
and generalises to products never seen in training — the explicit goal, since
the evaluation set contains products the training set does not.

Two small hand tables remain, deliberately disciplined:

- **`ALIASES`** now lives on the **server** (`mcp/resolve.py`), as a
  *seed/backstop* inside `resolve_name`: the ranked search always runs and
  unions with it. It holds only *structural naming facts* search cannot recover
  — where the name shares no word with the CPE product or its title
  (`httpd`→`apache:http_server`, `libssl`→`openssl:openssl`,
  `liblzma`→`tukaani:xz`). Products whose name matches their CPE product are not
  listed; the data path handles them.
- **`NEUTRAL`** is the only naming logic left in the agent. It drops unambiguous
  OS/distro plumbing and the OS kernel.
  It is kept small on purpose: the grader already ignores OS packages and
  tolerates extras, so a neutral list can only break even or, if it wrongly
  lists a real product, lose points — an early version mistakenly neutralised
  `libxml2`, `glibc` and `zlib`, which are scored, and those were removed.

## 4. Failure analysis

Grounded in the most recent full run, the public evaluation half (the feedback
run): overall score **87.07** (indicative — the grade uses the private half).
The structured, tool-generated formats, which carry most of the CVEs, are at or
near 100 (apk-info, dockerfile, maven-pom, nmap-xml, pip, rpm-qa, syft-json and
whatweb at 100; dpkg-list 95; cyclonedx-json 93.3; spdx-json 92.5; npm-lock 90).
The loss is in loose text, and two formats are worse than the previous run:

| Format | Score | Cause |
|---|---:|---|
| ps-aux | 26.7 | process listings carry no versions; the model still pairs a daemon with a number from the line |
| nmap-normal | 50.0 | regression from the ps-aux prompt clause, since narrowed (below) |
| banners | 61.7 | version in binary / separate-line noise the model must read |
| version-commands | 77.6 | loose `cmd: output` lines the model must pair |
| html | 88.9 | version in page text or metadata |
| analyst-notes | 90.0 | free prose |

The causes, each general rather than a per-document quirk:

- **Loose-text recall.** Banners and analyst notes depend on the model reading
  prose, which varies run to run. Standard banner shapes now parse
  deterministically — `OpenSSH_7.2p2`, `ProFTPD 1.3.5b`, the MariaDB handshake
  (`5.5.5-10.1.48-MariaDB`), the smbclient `Samba 4.13.17` line, and the
  memcached `STAT version` field — so the model is left only with the genuinely
  hard residue: a version embedded in a binary handshake (ActiveMQ OpenWire) or
  on a line away from its product (an SNMP `nsVersion`). That residue is the
  inherent limit of reading untrusted text, not a mechanism gap.
- **Zero-CVE naming edge cases** (e.g. Express's `openjsf` vendor) affect one
  product on one document, carry no CVE impact, and admit no general signal —
  the only "fix" would be a per-product hard-code, so they are left.

**Fixes that landed, and look-alikes that did not.** Two earlier bugs are gone:
the `name version` regex no longer turns prose into products (`Nmap done …
scanned in 346.53 seconds` and `Redis key-value store 5.0.7` are dropped by
stop-words), and a bare `httpd` banner (`CouchDB httpd 3.1.0`) is no longer
misfiled under Apache while the package name `httpd` still resolves from
`rpm`/`apk` lines. Look-alike resolution, though, is improved but **not
solved**. The generic-word guard stops a match on a shared *generic* token
(`Zend Engine` no longer beats `docker:engine` on "engine" in the ranked
search), yet the run shows look-alikes still reach the output two other ways:

- a shared *non-generic* token still over-matches — `packaging` →
  `ibm:packaging_utility`, `Apache Commons Text` → `golang:text`;
- the model's `suggest_name` fallback canonicalises a name to a bare generic
  word that then matches a product *exactly*, bypassing the guard: `Zend Engine`
  → "engine" → `docker:engine` (doc-016), `7-Zip` → "zip" →
  `info-zip_project:zip` (doc-049), with `Exim smtpd` → `opensmtpd:opensmtpd`
  and `ntpd` → `ntpd_driver_project:ntpd_driver` the same shape.

These are wrong extras on zero- or low-CVE products, so they cost
products-precision, not CVEs. The fix I have not made is the one the feedback
names: score a candidate by **vendor/title agreement** rather than any shared
token, and have `suggest_name` return a vendor-qualified name.

**ps-aux (26.7) — reduced, not eliminated.** The deterministic parser emits
nothing for a `ps aux` listing, and a model-extracted version is kept only if
it appears verbatim in the source; yet ps-aux is still the weakest format. The
model pairs a daemon with a number that genuinely appears in the line (a PID, a
CPU%, a version-like token in a command path), so the verbatim check passes.
The prompt telling the model that process and resource columns are not versions
helped host-report (98.9) and windows-inventory (95) but did not solve ps-aux;
a reliable fix would detect the `ps`/`top` header and suppress the document,
which I judged too format-specific to hard-code.

**nmap-normal regressed (90 → 50), now addressed.** The prompt clause meant to
quiet ps-aux — "a process or service listing … return an empty array unless a
version is shown" — the model over-applied to `nmap -sV` output, which *is* a
service listing but *does* carry versions, suppressing its contribution (the
deterministic pass kept the format from collapsing). The clause has since been
narrowed to name only process listings (`ps`/`top`) and to state explicitly
that a port scan lists real versions to report. Because the earlier wording did
not actually make ps-aux return empty either (ps-aux stayed at 26.7), dropping
it should recover nmap-normal at no cost to ps-aux — a one-line change made
after the feedback runs were spent, so reasoned-for but not re-measured.

**Deliberately not chased:** the "N reported CVEs do not apply" notes come from
NVD all-versions matches under an AND node with a platform — the handout calls
these optional and they carry no penalty.

## 5. Security boundary

The AgentLab boundary is unchanged: the agent reaches the model only through
the gateway and vulnerability data only through the MCP server; neither
container can reach the internet. No vulnerability data is baked into either
image — it is all loaded from the read-only `/feeds` mount. The MCP container
keeps its read-only root filesystem, dropped capabilities and non-root user.

<!-- §4 is grounded in the latest public-half feedback run (overall 87.07). A
fresh training-set `grade.py -v` can replace the per-format table with
per-document misses if desired. -->
