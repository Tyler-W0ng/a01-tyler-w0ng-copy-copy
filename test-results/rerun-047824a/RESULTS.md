# Real-model rerun: documents 1–10 after fixes

- Tested commit: `047824a` (`Fixing issues`). Git status before the run showed only the ten untracked training input copies.
- Date: October 21, 2026 (America/Los_Angeles). Completion timestamp: `10/21/2026 14:24:35`.
- Model selection: `external`, using the previously configured `claude-v4.6-sonnet` endpoint; mode: `agent`; tracing off.
- All 10 documents completed with status `ok`; no missing outputs; command sequence exited 0.
- Processing duration: 42.89 seconds, excluding image build and startup.
- Overall score: **89.33 / 100**, versus **73.00 / 100** previously: **+16.33 points**.

## Comparison

| Document | Format | Previous score | New score | Change | Output summary |
|---|---|---:|---:|---:|---|
| doc-001.txt | http-headers | 100.00 | 100.00 | 0.00 | 6 product(s), 42 CVE(s) |
| doc-002.txt | fs-listing | 86.67 | 13.33 | -73.33 | 3 product(s), 1 CVE(s) |
| doc-003.txt | nmap-normal | 73.33 | 100.00 | +26.67 | 4 product(s), 27 CVE(s) |
| doc-004.txt | html | 80.00 | 80.00 | 0.00 | 2 product(s), 1 CVE(s) |
| doc-005.txt | nmap-normal | 100.00 | 100.00 | 0.00 | 6 product(s), 37 CVE(s) |
| doc-006.txt | rpm-qa | 0.00 | 100.00 | +100.00 | 7 product(s), 31 CVE(s) |
| doc-007.txt | rpm-qa | 0.00 | 100.00 | +100.00 | 5 product(s), 13 CVE(s) |
| doc-008.txt | whatweb | 100.00 | 100.00 | 0.00 | 3 product(s), 66 CVE(s) |
| doc-009.txt | apk-info | 100.00 | 100.00 | 0.00 | 4 product(s), 2 CVE(s) |
| doc-010.txt | version-commands | 90.00 | 100.00 | +10.00 | 6 product(s), 35 CVE(s) |

Scores use 40% products, 40% CVEs, and 20% CWE. Overall component scores: products 0.8833, CVEs 0.9000, CWE 0.9000. Reported counts are not counts of correct matches.

## Findings

- Both RPM documents (6 and 7) improved from 0 to 100. Documents 3 and 10 also improved to 100.
- Document 2 regressed from 86.67 to 13.33: libxml2 and XZ Utils were missed. Document 4 still misses Apache Solr and scores 80.
- Eight documents scored 100, but some still have tolerated extras. Document 6 reports four non-applicable CVEs without a score penalty.
- This is one real-model run on ten training documents. Model variability and code changes may both affect comparisons; the scores do not establish performance on unseen inputs.

## Exact test procedure

Executed from Windows through `wsl --exec bash -lc` in the working repository. Checked Git status and the latest commit; the pull changed only `agent/app/graph.py`, `parsers.py`, and `resolver.py`. Reused the already-running MCP/gateway stack and the existing training input copies. The agent image rebuilt successfully, and Compose confirmed healthy dependencies. Only the ten explicit IDs were processed and graded. No conformance probe or full-dataset test was run.

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-047824a/items
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-001.txt doc-002.txt doc-003.txt doc-004.txt doc-005.txt doc-006.txt doc-007.txt doc-008.txt doc-009.txt doc-010.txt" 2>&1 | tee test-results/rerun-047824a/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-047824a/grade.json -v doc-00{1,2,3,4,5,6,7,8,9}.txt doc-010.txt | tee test-results/rerun-047824a/grade.log
cp output/run.json test-results/rerun-047824a/run.json
cp output/items/doc-00{1,2,3,4,5,6,7,8,9}.txt.json output/items/doc-010.txt.json test-results/rerun-047824a/items/
```

## Grader details

### doc-001.txt

- extra product eclipse:hudson:1.395

### doc-002.txt

- missed libxml2 2.9.4
- missed XZ Utils 5.6.0

### doc-003.txt

- extra product ca:advantage_data_transport:5.17.5

### doc-004.txt

- missed Apache Solr 7.7.2
- extra product ingo_renner:apache_solr:7.7.2

### doc-005.txt

- extra product mysql:mysql:5.5.5-10.5.15-MariaDB
- extra product ca:advantage_data_transport:5.15.3

### doc-006.txt

- 4 reported CVE(s) do not apply

### doc-007.txt

- No grader findings.

### doc-008.txt

- No grader findings.

### doc-009.txt

- extra product openssl:openssl:1.34.1

### doc-010.txt

- extra product goforandroid:go_bookmark_widget:1.17.10

## Saved evidence

- [Grading JSON](grade.json), [verbose grader log](grade.log), [run log](run.log), and [run metadata](run.json).
- The ten generated output JSON files are preserved in `items/`. Earlier results remain unchanged in the parent `test-results/` directory.
