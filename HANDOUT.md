# A01: CVE triaging

**Individual.** Read [the submission guide](SUBMISSION.md) first. Dates are
on the course schedule.

You will build an agentic system that reads what a security analyst gets
about a system — a port scan, an SBOM, a file listing, banners, an analyst's
notes — and answers two questions:

1. **What software is there?** Product and version, as an NVD CPE.
2. **Which known vulnerabilities apply?** The 2026 CVEs (`CVE-2026-*`),
   and the CWE behind each.

You build it on top of **AgentLab** (<https://github.com/giovannivigna/agentlab>),
which gives you the platform: a model gateway, the I/O plumbing, a knowledge
base, tracing and a security boundary. You replace its two task-specific
containers with your own:

| Container | Replaces | What it is |
|---|---|---|
| `mcp` | the processing MCP server | a **vulnerability knowledge server**: CVE, CWE, CAPEC, KEV and CPE data behind MCP tools, loaded from the course's data files |
| `agent` | the pipeline | your **triage agent**: reads `input/items/`, writes one result per document to `output/items/` |

Everything else in AgentLab stays as it is, including the boundary: neither
container can reach the internet. The agent talks to a model only through the
gateway, and gets vulnerability data only from your MCP server.

---

## 1. What you get

| | |
|---|---|
| `datasets/train/items/` | 50 example documents, in 23 formats |
| `datasets/train/expected.json` | their answer key, in the form the grader reads (described in §4) |
| `grader/grade.py` | the grader (standard-library Python), the same code the autograder runs |
| `grader/mcp_probe.py` | the conformance test the autograder runs against your MCP server |
| `feeds/` | the vulnerability data your MCP server loads (§2): the five source files, frozen, with `SNAPSHOT.json` and `SHA256SUMS` |

The evaluation dataset is another 100 documents of the same kinds, in two
halves of 50: feedback runs score the public half, your grade the private
half (§7). It includes products and versions that are not in the training
set, and you will not see it.

Everything is computed from one frozen snapshot of the sources, taken on
**2026-10-12**: the files in `feeds/` are the ones the answer keys were
computed from, and the ones the grader gives your MCP server. Your server and
the key therefore see the same data. If you report a CVE that the key does not
list, the difference is in how the CVE was matched to the product and version
(§4), not in the data.

**What you need:** Docker with Compose 2.24 or newer, and about 10 GB of
memory and 15 GB of disk for Docker (your MCP server alone may use up to
6 GB while it loads); Python 3.11 or newer for the course tools; and, to run
a real model locally, an API key of your own (§3). A run over the 50
training documents with the grading model costs about $0.20–0.35;
`mock-model` costs nothing.

## 2. The MCP container

### The data

Your server answers from the five public sources the course provides, frozen,
in `feeds/` (127 MB, as their publishers ship them):

| File | Source | What you need from it |
|---|---|---|
| `nvdcve-2.0-2026.json.gz` | NVD CVE feed (JSON 2.0), the 2026 CVEs | description, CVSS, CWE ids, and the **CPE applicability configurations** |
| `nvdcpe-2.0.tar.gz` | NVD CPE dictionary (JSON 2.0, in chunks) | official vendor/product/version names and titles |
| `cwec_latest.xml.zip` | MITRE CWE 4.20 | names, descriptions, relationships |
| `capec_latest.xml` | MITRE CAPEC 3.9 | attack patterns and the CWEs they target |
| `known_exploited_vulnerabilities.json` | CISA KEV catalog | which CVEs are known to be exploited |

`SNAPSHOT.json` says where each file came from and its version. Do not edit
or replace them: the grader uses its own copy, checked against `SHA256SUMS`.

**Your server loads them when it starts.** The directory is mounted
read-only into your MCP container at the path in `$VULNDB_FEEDS` (`/feeds`),
by `compose.override.yaml` on your machine and by the grader the same way.
Parse what you need into whatever you like (an in-memory SQLite database
works well), then start answering. The constraints:

- **No vulnerability data in the image, and nothing fetched at run time.**
  The container has no route out, and the data comes only from `/feeds`.
  Installing packages when the image is built (`pip install`) is fine.
- **The root filesystem is read-only**; `/tmp` is a small tmpfs. Keep the
  database in memory. (SQLite: `PRAGMA temp_store = MEMORY`, or index
  builds fail.)
- **Healthy means ready.** The stack waits up to 5 minutes for your server
  to become healthy (below); the reference loads in about 30 s.
- **Memory:** 6 GB for the container (`compose.override.yaml` sets the same
  limit locally). Parsing the CPE dictionary (900 MB of JSON) is the largest
  step: stream it, chunk by chunk.

**Scope: the 2026 CVEs.** The assignment, and the grader, cover only the
CVEs in NVD's 2026 feed (`CVE-2026-*`, about 70,000 of them). The CPE
dictionary is far larger: 1.8 million entries for about 150,000 products, one
entry per version of each (`cpe:2.3:a:lighttpd:lighttpd:1.4.55:*:...`). Only
about 6,000 of those products have a 2026 CVE, so you need much less than all
of it:

- **Every product's name.** Documents also show products that no 2026 CVE
  mentions. `doc-001.txt` shows lighttpd 1.4.55; no 2026 CVE names lighttpd,
  so the right answer is `lighttpd:lighttpd`, version `1.4.55`, with an empty
  `cves` list. Your agent can only give that answer if your server can
  resolve "lighttpd" to its CPE name.
- **Versions only where they matter.** The dictionary lists 96 versions of
  lighttpd. They cannot lead to a 2026 CVE, so you can skip them. For a
  product with 2026 CVEs, such as OpenSSL (344 versions, 51 CVEs), they are
  worth keeping, for example for a tool that lists known versions.

The reference keeps every product and the versions of the products that 2026
CVEs mention: about a third of the dictionary.

### How it runs

- **MCP over Streamable HTTP, at `http://mcp:8000/mcp`:** port 8000, path
  `/mcp`. The agent finds it in `$MCP_URL`.
- **`GET /health` on port 8000** answers 200 only once your data is loaded.
  The healthcheck (AgentLab's, the grader's too) runs
  `python -c "...urlopen('http://localhost:8000/health')..."` inside your
  container, so your MCP image needs `python` on its `PATH`, whatever your
  server is written in.

### The interface

You may offer any tools you like. These seven are **required**, with these
names, because the autograder's conformance probe calls them. The shape of
each answer is up to you, as long as it contains the facts listed.

| Tool | Arguments | Must answer with |
|---|---|---|
| `db_info` | — | when the data was built, and from which feeds |
| `get_cve` | `cve_id` (`"CVE-2026-24061"`) | description, CVSS score, CWE id(s), whether it is in KEV |
| `get_cwe` | `cwe_id` (`"CWE-79"`) | name and description; related CAPEC patterns |
| `get_capec` | `capec_id` (`"CAPEC-66"`) | name and description; related CWEs |
| `get_kev` | `cve_id` | the KEV entry (date added, ...) or that there is none |
| `search_products` | `query` (`"openssh"`) | CPE `vendor:product` candidates for a name |
| `vulnerabilities_for` | `vendor`, `product`, `version` (all strings) | the CVEs that apply to that exact version (§4) |

The probe looks for facts **as text anywhere in an answer**, case-insensitive:
the CVSS score as `9.8`, CWE ids written `CWE-88` (not a bare `88`), the
word `kev` in a CVE's answer, the KEV date as `2026-01-26`. Its ten checks
are listed at the top of `grader/mcp_probe.py`.

Expect to want more than these. A tool that maps package and banner names to
CPE products (`libssl1.1`, `Apache httpd` and `python3-django` are not CPE
names), and a way to list known versions, are good places to start.

Run `grader/mcp_probe.py` against your server (§6) before submitting.

## 3. The agent container

### Contract

- It is a **job**, as in AgentLab: `make run` starts it, it processes every
  document in `/work/input/items/` (read-only), writes
  `/work/output/items/<id>.json` for each, and exits. `<id>` is the input's
  full file name: `doc-014.txt` gives `doc-014.txt.json`.
- It reaches the model only at `AGENT_BASE_URL` with `AGENT_API_KEY` and
  `AGENT_MODEL` (all from the environment), and the vulnerability data only
  through your MCP server at `MCP_URL`.
- A graded run gives it **50 documents** (one half of the evaluation set),
  which it must finish within **60 minutes** and the run's model budget
  (below). An output that is never written scores as an empty answer.
- Keep AgentLab's I/O server, or replace it with something equivalent.

### The model

The grader runs your agent against **Claude Sonnet 5.5** (`claude-sonnet-5-5`).
Your agent never names it: it asks the gateway for `AGENT_MODEL` (`external`)
over the OpenAI chat-completions API, and the gateway reaches Claude. The
run's key allows:

- **$3** in total; once it is spent, model calls fail, and your agent has
  to cope. (The reference spends $0.20–0.35 per 50 documents.)
- 120 requests and 200,000 tokens a minute, and **4 requests at a time**.
  Calls above those limits are refused, not queued.

Your repository's `gateway/agents.yaml` gives your local key the same limits
(the $3 per day), so what runs locally fits the grader.

- `response_format={"type": "json_object"}` is accepted, but Claude does not
  enforce it: a reply can still arrive in a code fence or after a sentence.
  Parse the first JSON object you find, and treat a reply without one as a
  failed call.
- Refusals and filtered replies happen. One bad call must cost you one
  document's model help, not the run.

To develop against the same model with your own Anthropic key, edit the
existing `EXTERNAL_*` lines in `.env` (`make up` creates it from
`.env.example`; or `cp .env.example .env` first) and add one:

```bash
EXTERNAL_BASE_URL=https://api.anthropic.com
EXTERNAL_MODEL=claude-sonnet-5-5
EXTERNAL_API_KEY=sk-ant-...
EXTERNAL_LITELLM_MODEL=anthropic/claude-sonnet-5-5
```

then `make up` (again, if the stack is running) and `AGENT_MODEL=external
make run`. `compose.override.yaml` passes `EXTERNAL_LITELLM_MODEL` to the
gateway, as the grader does. Any other OpenAI-compatible model works through
`make connect` once you delete the `EXTERNAL_LITELLM_MODEL` line, and
`mock-model` costs nothing; just measure on Claude before you submit.

### What may be in the images

Code, the packages it needs, and small hand-written tables, such as a map
from package or banner names to CPE names, may be in either image. These may
not: vulnerability data (CVEs, CVSS, CWE, CAPEC, KEV, CPE applicability),
which comes only from your MCP server's `/feeds`; anything derived from the
answer keys; and anything that recognizes particular training documents.

### Output

One JSON object per document. The grader reads the fields in **bold**; add
whatever else helps you, such as evidence or notes.

```json
{
  "id": "doc-999.txt",
  "products": [
    {
      "cpe": "cpe:2.3:a:openbsd:openssh:7.6p1:*:*:*:*:*:*:*",
      "evidence": ["22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.7"],
      "cves": [
        {"id": "CVE-2026-35387", "cwes": ["CWE-670"]}
      ]
    }
  ]
}
```

- **`products`**: the software the document shows with a version, one entry
  per product and version (the same product on several hosts is one entry).
- **`cpe`** names the product and its version: a CPE 2.3 string, or a 2.2
  URI (`cpe:/a:openbsd:openssh:7.6p1`). The version is the *upstream* one;
  the grader also accepts packaging forms such as `1:7.6p1-4ubuntu0.7`, and
  `7.6` with the update field `p1`. Instead of a version in the CPE you may
  give a `version` field, and instead of `cpe`, `vendor` and `product`.
- **`cves`**: the 2026 CVEs that apply to that product and version, each with
  **`id`** and **`cwes`**. Plain CVE-id strings are accepted, but then the
  CWE part scores zero.

## 4. Definitions the grader uses

**Products.** The key lists the software each document shows *with a
version*. A product reported under any of the CPE names NVD uses for it
counts: nginx is `f5:nginx`, `nginx:nginx` and, in its 2026 CVEs,
`f5:nginx_open_source`. Other software that merely shares a word does not
(`ibm:http_server` is not Apache's). Software shown without a version
(`Server: nginx`, `Drupal 9`), the operating system and its base packages
(coreutils, systemd, dpkg, musl, ...), and software shown only in passing
(the Python of a `site-packages` path) are ignored, whether you report them
or not.

**CVEs.** Only 2026 CVEs (`CVE-2026-*`) count; CVEs from other years are
ignored. A CVE applies to a product version when one of the CVE's
`vulnerable` CPE match entries for that product, in NVD's data,

- names that version exactly, or
- gives a version range that contains it (compare the numbers in the
  versions: 2.4.29 is below 2.4.58), or
- names every version (`*` with no range).

The few CVEs where finer points of NVD's data would change the answer (a
version written as `7.2` plus update `p2`, letter suffixes such as the `k`
in `1.0.2k`) are optional: reporting them or not costs nothing. The grader
follows NVD on the upstream version, even where a distribution has
backported a fix.

Some products in the documents have no 2026 CVE at all: the right answer is
the product with an empty `cves` list.

**CWEs.** For each CVE you report correctly, at least one of your CWEs must
be one that NVD or the CVE's numbering authority assigned (`NVD-CWE-Other`
and `NVD-CWE-noinfo` are not CWEs).

**The answer key** (`expected.json`): `items` maps each document to its
`products`, each with its accepted `cpe` names, `version`, `cves` (CVE → its
CWEs; `{}` when none applies) and `optional_cves`; the products it shows
without a version (`ignored`). `neutral_products` and each document's
`tolerated` list the other software the grader ignores.

## 5. Scoring

Each document is scored on three parts, and each part is averaged over the
documents:

| Part | Weight | What it measures |
|---|---|---|
| products | 0.40 | the share of the key's products you report, with the right version |
| cves | 0.40 | for the products you found, the share of their CVEs you report |
| cwe | 0.20 | for the CVEs you report correctly, the share with a correct CWE |

**Extras are free, within reason.** You may report up to twice as many
products as the document has (at least 2), and up to twice as many CVEs as
the products you found have, at no cost. Beyond that, the part is scaled
down by *allowed / reported*: reporting every product you can think of does
not pay. A document whose products have no CVEs is left out of the CVE and
CWE parts.

The score is 100 × the weighted sum.

## 6. Working locally

In your repository (§7), which is AgentLab plus `datasets/`, `feeds/` and
`grader/` (`AGENTLAB.md` is AgentLab's own guide):

```bash
git clone git@github.com:cs279-f26/a01-<github-username>.git && cd a01-<github-username>
# replace agent/ and mcp/ with yours, then:
rm -f input/items/* && cp datasets/train/items/* input/items/
make up                                  # MODE=agent; your MCP server loads feeds/ (§2) before it is healthy
AGENT_MODEL=mock-model make run          # free smoke test: the reference's parsers alone score ~69
make connect                             # a real model (or the .env lines in §3)
AGENT_MODEL=external make run
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items -v
```

`grade.py -v` lists every miss, document by document. (AgentLab's own
`make eval` scores its demo inputs, not these: ignore it.) Your repository
runs the stack the way the grader does: `MODE=agent`, your images as built
(`make run` rebuilds the agent; the code is not mounted live), the feeds
mounted, the memory limit set. Kept in mind: `MODE=kb` and `full` add a
memory database and tracing, which the grader does not run.

To probe your MCP server from inside the stack's network:

```bash
docker compose run --rm --no-deps -v "$PWD/grader:/grader:ro" \
    --entrypoint python agent /grader/mcp_probe.py http://mcp:8000/mcp
```

This uses your agent image's Python and its `mcp` package (2.x); use any
image that has both. The grader runs the probe from a container of its own.

`make check` tests the wiring. Its MCP checks assume AgentLab's tools: in
`scripts/check.sh`, change the list of tools the "agent finds ... on the MCP
server" check expects, and the I/O check if you replace the I/O server.

## 7. Submitting

**Individual.** Read the [submission guide](SUBMISSION.md). You work in
your private repository, `a01-<github-username>`, created by the course from
a template that contains AgentLab, the training data, the feeds, and the
grader. Your `agent/` and `mcp/` replace AgentLab's. Your submission is the
last commit on `main` pushed before the deadline.

| Path | What the grader does with it |
|---|---|
| `agent/Dockerfile`, `mcp/Dockerfile` | builds the two images (`docker build agent`, `docker build mcp`) |
| `REPORT.md` or `REPORT.pdf` | the write-up (§8) |
| `submission.toml` | `members = ["<github-username>"]` (it starts empty) |
| `AI_USAGE.md` | your AI-tool disclosure |
| `compose.yaml` | required by preflight; not used for grading (keep it) |
| `feeds/` | ignored: the grader mounts its own copy of the snapshot at `/feeds` |

Preflight (`python3 .cs279/preflight.py`, and on every push) checks that the
files the grader needs exist. Until you fill in `members` and add the
write-up it shows a red ✗, which is expected early on.

The course grader builds both images from your repository and runs them in
the course's own copy of AgentLab (your `compose.yaml`, `gateway/` and the
other platform files are not used) on the hidden evaluation set, with the
course's model behind the gateway and the feed snapshot mounted into your
MCP container. Everything else your system needs at run time must be inside
the two images.

- **Feedback runs:** push a `feedback-*` tag, at most **3 for the whole
  assignment**; later tags are ignored. A feedback run scores the **public half**
  of the evaluation set and posts an issue in your repository with every
  criterion of §8: your score overall and per format, the MCP probe result,
  and the AI review's comments on the other parts. Feedback scores are
  indicative.
- Every run uses **Claude Sonnet 5.5** with a **$3 model budget** (§3). If the
  model provider itself fails during a run (an outage, not your agent), the
  run is void and repeated, and does not count against your 3.
- Your grade uses your final submission, scored on the **private half** of
  the evaluation set, which feedback runs never show.

## 8. Grade

| Part | Weight | How |
|---|---|---|
| Effectiveness on the private half (below) | 60 | automated |
| MCP conformance probe: 10 × checks passed / 10 | 10 | automated |
| MCP server: what it loads and answers from `/feeds`, and that the agent carries no vulnerability data (5); the design of its tools beyond the required seven, such as name-to-CPE mapping and version listing, and how usable they are for a model (10) | 15 | AI-assessed |
| Write-up (`REPORT.md` or `REPORT.pdf`, at most 4 pages, about 2,000 words): design, what the model does and what code does, failure analysis on the training set | 15 | AI-assessed |

**Effectiveness** is a number from 0 to 100 computed from S, your score on
the private half: 0 for S ≤ 50, 100 for S ≥ 90, and linear in between,
100 × (S − 50) / 40. It is worth 60% of the grade: S = 80 gives an
effectiveness of 75, which is 45 of the 60 points. (The reference solution
scores about 98–100; its parsers alone, with no model, about 65–69.)
AI-assessed parts are reviewed by the instructors before grades are
released.

**Not allowed:** answers hard-coded for the training documents, an agent or
MCP server that can reach the internet, provider keys or other secrets in
your images or repository, or any model access other than the gateway. A
submission that breaks one of these rules can lose any part of the grade. A
submission whose agent carries the vulnerability data itself, instead of
asking the MCP server, loses the MCP server part.
