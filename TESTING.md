# Testing the A01 CVE-triage system

How to run and score the system locally. Everything runs under Docker; the
MCP server loads the frozen feeds in `feeds/` at startup.

## What's in each container

- **`mcp/`** — the vulnerability knowledge server. Loads the 5 feeds into an
  in-memory SQLite DB (`loader.py`), answers the 7 required tools plus a few
  extras (`server.py`), matches versions to CVE ranges (`version.py`).
- **`agent/app/`** — the triage pipeline:
  - `parsers.py` — detect format + deterministic extraction + version normalize
  - `resolver.py` — name -> CPE alias table, OS-package filter, ranking
  - `llm.py` — the two model touchpoints (extract from messy docs, suggest a name)
  - `graph.py` — the LangGraph flow: `list_inputs -> read_next -> extract -> resolve -> lookup -> write`

## Test sequence

```bash
# 1. Load the training docs as the agent's input
rm -f input/items/* && cp datasets/train/items/* input/items/

# 2. Build and start the stack (MCP server loads feeds/, ~30-60s to healthy)
make up MODE=agent

# 3. MCP conformance probe — target 10/10
docker compose run --rm --no-deps -v "$PWD/grader:/grader:ro" \
    --entrypoint python agent /grader/mcp_probe.py http://mcp:8000/mcp

# 4. Free smoke test (no model cost): exercises the deterministic spine + wiring
AGENT_MODEL=mock-model make run

# 5. Score the outputs against the training answer key
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items -v
```

### Running against the real model (Claude Sonnet 5.5)

Add these lines to `.env` (created by `make up`; or `cp .env.example .env` first),
using your own Anthropic key:

```bash
EXTERNAL_BASE_URL=https://api.anthropic.com
EXTERNAL_MODEL=claude-sonnet-5-5
EXTERNAL_API_KEY=sk-ant-...
EXTERNAL_LITELLM_MODEL=anthropic/claude-sonnet-5-5
```

Then:

```bash
make up MODE=agent                 # re-create so the gateway reads the new keys
AGENT_MODEL=external make run
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items -v
```

A run over the 50 training docs with Claude costs about $0.20-0.35.

## What to expect

- **Step 3 (probe):** should pass **10/10**. The data behind every check was
  verified directly against the feeds (CVE-2026-24061 -> 9.8 / CWE-88 / KEV;
  apache http_server 2.4.49 includes CVE-2026-29167 and 29168, 2.4.67 excludes
  29168; openssh 7.2p2 includes CVE-2026-35387).
- **Step 4 (mock-model):** the mock model returns canned text, so the model
  extraction yields little and is ignored. This verifies the plumbing and gives
  a partial deterministic score — NOT the full parsers-only ~65-69, which needs
  real parsing across all formats.
- **Step 5 / real model:** `grade.py -v` lists every miss per document. The
  reference scores ~98-100; parsers alone ~65-69.

## Scoring (from the handout)

Per document, averaged over the set:

| Part | Weight | Measures |
|---|---|---|
| products | 0.40 | share of the key's products you report, with the right version |
| cves | 0.40 | for the products you found, the share of their CVEs you report |
| cwe | 0.20 | for the CVEs you report correctly, the share with a correct CWE |

Extras are free up to ~2x the document's real product count; beyond that the
part is scaled down by `allowed / reported`.

## Known tuning points

- **Loose-text regex noise** (`parsers._parse_text`): banners/scans can produce
  spurious candidates. Most fail to resolve and get dropped, but generic names
  can leak through as extras. First thing to check with `grade.py -v` if the
  product score looks low.
- **OS-package filter** (`resolver.NEUTRAL`): best-effort list of base packages
  to drop. Add names here if package-list docs report too many extras.
- **Alias table** (`resolver.ALIASES`): add common `name -> vendor:product`
  mappings here when a product consistently resolves wrong or not at all.

## Troubleshooting

- **Agent won't start, "does not offer ..."** — the remote-tool check in
  `agent/app/clients.py` (`PROCESSORS`) lists tools the MCP server must expose.
- **MCP server never healthy** — it loads feeds before serving; check
  `docker compose logs mcp` (it prints `vulndb: loading feeds...` then
  `vulndb: ready`). Load takes ~30-60s; the healthcheck tolerates 300s.
- **`make check`** — wiring checks; the MCP tool-list check was updated in
  `scripts/check.sh` to the new vulnerability tools.
