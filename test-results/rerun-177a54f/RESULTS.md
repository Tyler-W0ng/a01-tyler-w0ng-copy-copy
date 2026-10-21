# Fourth iteration: documents 2 and 20

- Commit: `177a54f` (`fouth iteration`). Application changes since `4d5c5d4` were in `agent/app/parsers.py` and `resolver.py`.
- Date: October 21, 2026. Agent log interval: 23:06:43–23:06:57 UTC (16:06:43–16:06:57 America/Los_Angeles).
- Selected model: `external`, using the previously configured real-model endpoint; mode: `agent`; tracing off.
- Both requested documents completed with status `ok`, no missing outputs, and command sequence exit code 0.
- Combined score: **100.00 / 100**. Products, CVEs, and CWE components all scored 1.0000. No grader findings.

## Comparison

| Document | Format | Previous score at 4d5c5d4 | New score | Agent output summary |
|---|---|---:|---:|---|
| doc-002.txt | fs-listing | 86.67 | 100.00 | 7 products, 17 CVEs |
| doc-020.txt | host-report | 80.00 | 100.00 | 5 products, 12 CVEs |

The previous XZ Utils 5.6.0 and Elasticsearch 5.6.16 misses are resolved in this run. Reported counts are agent totals, not necessarily counts of graded matches. Only these two documents were rerun; this does not establish a full-dataset score or regression result on the new commit.

## Exact testing procedure

Verified the local commit, status, and changed files through WSL. Git status showed only existing untracked training input copies. The two inputs were already present. The agent image rebuilt successfully; existing MCP/gateway services were reused and Compose confirmed healthy dependencies. Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-177a54f/items
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-002.txt doc-020.txt" 2>&1 | tee test-results/rerun-177a54f/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-177a54f/grade.json -v doc-002.txt doc-020.txt | tee test-results/rerun-177a54f/grade.log
cp output/run.json test-results/rerun-177a54f/run.json
cp output/items/doc-002.txt.json output/items/doc-020.txt.json test-results/rerun-177a54f/items/
```

Checked that the logged inputs matched the requested two IDs, both completed successfully, and the grader reported no missing outputs or findings. Scores use 40% products, 40% CVEs, and 20% CWE. No application code was changed; no conformance probe or other documents were run. This is one real-model-configured test; per-document model call counts and cost were not collected.

## Evidence

- [Grader JSON](grade.json)
- [Verbose grading log](grade.log)
- [Run log](run.log)
- [Run metadata](run.json)
- [Document 2 output](items/doc-002.txt.json)
- [Document 20 output](items/doc-020.txt.json)

## Additional batch: documents 20–30

- Commit: `177a54f`. Date: October 21, 2026. Agent log interval 23:08:40–23:09:38 UTC (16:08:40–16:09:38 America/Los_Angeles).
- Selected model: `external`, same configured real-model endpoint; mode `agent`; tracing off.
- All 11 documents completed with status `ok`; no missing outputs; command sequence exited 0.
- Processing time: 57.7 seconds, excluding image build/startup.
- Batch score: **98.18 / 100**. Products 0.9545, CVEs 1.0000, CWE 1.0000.

| Document | Format | Score / 100 | Agent output summary |
|---|---|---:|---|
| doc-020.txt | host-report | 100.00 | 5 product(s), 12 CVE(s) |
| doc-021.txt | version-commands | 100.00 | 4 product(s), 5 CVE(s) |
| doc-022.txt | dockerfile | 100.00 | 2 product(s), 21 CVE(s) |
| doc-023.txt | dockerfile | 80.00 | 3 product(s), 13 CVE(s) |
| doc-024.txt | html | 100.00 | 3 product(s), 25 CVE(s) |
| doc-025.txt | fs-listing | 100.00 | 7 product(s), 5 CVE(s) |
| doc-026.json | spdx-json | 100.00 | 7 product(s), 52 CVE(s) |
| doc-027.txt | analyst-notes | 100.00 | 1 product(s), 0 CVE(s) |
| doc-028.json | spdx-json | 100.00 | 5 product(s), 12 CVE(s) |
| doc-029.txt | host-report | 100.00 | 4 product(s), 28 CVE(s) |
| doc-030.txt | banners | 100.00 | 8 product(s), 49 CVE(s) |

Per-document scores use the available component weights (40% products, 40% CVEs, 20% CWE), excluding null components. Counts are reported totals, not counts of correct matches. The overall score averages component metrics over eligible documents. Only document 23 scored below 100; its misses are listed below. Some 100-scoring documents still have tolerated extras.

### Grader findings

- **doc-021.txt**: 1 reported CVE(s) do not apply
- **doc-023.txt**: missed GNU C Library 2.31
- **doc-023.txt**: missed SQLite 3.22.0
- **doc-023.txt**: missed zlib 1.2.12
- **doc-026.json**: 4 reported CVE(s) do not apply
- **doc-027.txt**: extra product cisco:80-7111-01_for_the_unity-svrx255-1a:10.23.13.0
- **doc-028.json**: extra product openssl:openssl:1.34.1
- **doc-030.txt**: extra product public_project:public:10.0.0.1
- **doc-030.txt**: extra product jorisvm:jvm_gutenberg_rich_text_icons:11.0.19

### Exact commands and verification

Verified commit and Git status, inspected filenames (26 and 28 are JSON), and copied the selected training inputs. Rebuilt the agent image successfully and reused the healthy MCP/gateway stack. Executed this Bash body via Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-177a54f/docs-020-030/items
ids="doc-020.txt doc-021.txt doc-022.txt doc-023.txt doc-024.txt doc-025.txt doc-026.json doc-027.txt doc-028.json doc-029.txt doc-030.txt"
for id in $ids; do cp "datasets/train/items/$id" input/items/; done
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="$ids" 2>&1 | tee test-results/rerun-177a54f/docs-020-030/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-177a54f/docs-020-030/grade.json -v $ids | tee test-results/rerun-177a54f/docs-020-030/grade.log
cp output/run.json test-results/rerun-177a54f/docs-020-030/run.json
for id in $ids; do cp "output/items/$id.json" test-results/rerun-177a54f/docs-020-030/items/; done
```

Confirmed the logged input list contained only the 11 requested documents and all finished successfully. Read the grader JSON and verbose diagnostics; no missing outputs. No application edits or conformance checks were performed. This was one batch execution; the repeated request while it was running did not launch a duplicate run. Per-document API call counts and spend were not collected; deterministic paths may bypass model requests.

### Batch evidence

- [Grader JSON](docs-020-030/grade.json)
- [Verbose grading log](docs-020-030/grade.log)
- [Run log](docs-020-030/run.log)
- [Run metadata](docs-020-030/run.json)
- Output snapshots: `docs-020-030/items/`.
