# Third iteration: targeted real-model retest

- Commit: `4d5c5d4` (`Third iteration`). Application changes since `d4dc35c`: `agent/app/graph.py`, `parsers.py`, and `resolver.py`.
- Date: October 21, 2026. Agent log interval: 22:36:14–22:36:24 UTC (15:36:14–15:36:24 America/Los_Angeles).
- Scope: documents 2, 14, and 15, the remaining documents below 100 in the preceding iteration.
- Selected model: `external`, using the previously configured real-model endpoint; `MODE=agent`; tracing off.
- All three completed with status `ok`, no missing outputs, and command sequence exit code 0.
- Combined score for this three-document batch: **95.56 / 100**. Other documents were not rerun on this commit.

## Comparison

| Document | Format | Previous score | New score | Grader findings |
|---|---|---:|---:|---|
| doc-002.txt | fs-listing | 86.67 | 86.67 | Missed XZ Utils 5.6.0 |
| doc-014.xml | nmap-xml | 86.67 | 100.00 | None |
| doc-015.xml | maven-pom | 50.00 | 100.00 | None |

The MySQL and Apache Commons Collections misses are resolved in this run. Document 2 remains below 100 because XZ Utils 5.6.0 is still missing. The agent classified documents 14 and 15 as `nmap-xml` and `maven-pom`, respectively, rather than generic XML.

Document 15 has no applicable CVE/CWE grading component (`null` in JSON, `nan` in the text report); its score uses the grader's available-component weighting. Overall batch metrics are products 0.8889, CVEs 1.0000, and CWE 1.0000. The batch score uses component averages over eligible documents, not a simple mean of displayed document scores.

## Exact test procedure

Checked the local commit and changes using WSL. Git status showed only existing untracked input copies. The agent image rebuilt successfully, and the existing MCP/gateway services were reused with healthy dependencies. Input copies were already present. Executed the following Bash body using Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-4d5c5d4/items
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-002.txt doc-014.xml doc-015.xml" 2>&1 | tee test-results/rerun-4d5c5d4/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-4d5c5d4/grade.json -v doc-002.txt doc-014.xml doc-015.xml | tee test-results/rerun-4d5c5d4/grade.log
cp output/run.json test-results/rerun-4d5c5d4/run.json
cp output/items/doc-002.txt.json output/items/doc-014.xml.json output/items/doc-015.xml.json test-results/rerun-4d5c5d4/items/
```

Verified that only the three requested IDs were processed, all outputs were produced, and grading succeeded. No application-code edits, conformance probe, or full-dataset run were performed. The real-model configuration does not imply every document makes a model request: deterministic format handling can process structured inputs. No per-document API request counts were collected.

## Evidence

- [Grading JSON](grade.json)
- [Verbose grading log](grade.log)
- [Run log](run.log)
- [Run metadata](run.json)
- Output snapshots are preserved in `items/`.

## Additional batch: documents 15–20

Tested commit `4d5c5d4` with `AGENT_MODEL=external`, `MODE=agent`, and the same configured real-model endpoint. All six documents completed with status `ok`; no missing outputs; command sequence exited 0. Completed October 21, 2026 at `22:50:58.013439+00:00` (15:50:58 America/Los_Angeles). Agent processing time: 21.43 seconds, excluding build/startup.

**Batch score: 96.67 / 100.** Components: products 0.9167, CVEs 1.0000, CWE 1.0000. This score covers only documents 15–20.

| Document | Format | Products reported | CVEs reported | Score / 100 | Grader findings |
|---|---|---:|---:|---:|---|
| doc-015.xml | maven-pom | 2 | 0 | 100.00 | None |
| doc-016.txt | windows-inventory | 5 | 22 | 100.00 | Two tolerated extra products (listed below) |
| doc-017.txt | version-commands | 3 | 13 | 100.00 | None |
| doc-018.txt | ps-aux | 0 | 0 | 100.00 | None; the key expects zero products |
| doc-019.txt | whatweb | 5 | 68 | 100.00 | None |
| doc-020.txt | host-report | 3 | 11 | 80.00 | Missed Elasticsearch 5.6.16 |

Document 16 extras: `info-zip_project:zip:21.07` and `nuance:visual_c++_runtime_for_dragon_naturallyspeaking:14.29.30133`. These did not lower its score. Reported counts are from agent output and are not counts of correct matches.

Documents 15 and 18 have no applicable CVE/CWE scoring components (`null` in JSON; `nan` in text). The displayed per-document scores come from their single-document format scores, using the grader's available-component weighting. Overall components are averaged over eligible documents.

### Exact testing procedure for documents 15–20

Verified the current commit and Git status, then inspected the dataset filenames: document 15 is XML and 16–20 are text. Copied only those six inputs, retaining other input files. Rebuilt the agent image successfully and reused the existing healthy MCP/gateway stack. Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-4d5c5d4/docs-015-020/items
cp datasets/train/items/doc-015.xml datasets/train/items/doc-01{6,7,8,9}.txt datasets/train/items/doc-020.txt input/items/
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-015.xml doc-016.txt doc-017.txt doc-018.txt doc-019.txt doc-020.txt" 2>&1 | tee test-results/rerun-4d5c5d4/docs-015-020/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-4d5c5d4/docs-015-020/grade.json -v doc-015.xml doc-01{6,7,8,9}.txt doc-020.txt | tee test-results/rerun-4d5c5d4/docs-015-020/grade.log
cp output/run.json test-results/rerun-4d5c5d4/docs-015-020/run.json
cp output/items/doc-015.xml.json output/items/doc-01{6,7,8,9}.txt.json output/items/doc-020.txt.json test-results/rerun-4d5c5d4/docs-015-020/items/
```

Verified the six logged input IDs, successful item completion, grader results, and absence of missing outputs. No application code was edited. No other documents, conformance checks, or full-dataset tests were run in this batch. Deterministic paths may bypass model calls for individual inputs even when `external` is selected.

### Evidence for documents 15–20

- [Grader JSON](docs-015-020/grade.json)
- [Verbose grading log](docs-015-020/grade.log)
- [Run log](docs-015-020/run.log)
- [Run metadata](docs-015-020/run.json)
- Output snapshots: `docs-015-020/items/`.
