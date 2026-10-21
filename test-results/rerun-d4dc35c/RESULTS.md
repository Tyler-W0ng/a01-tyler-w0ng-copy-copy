# Targeted real-model retest: documents 2 and 4

- Tested commit: `d4dc35c` (`Second interation`). The application change since `047824a` was in `agent/app/resolver.py`.
- Date: October 21, 2026. Agent log interval: 22:02:05–22:02:17 UTC (15:02:05–15:02:17 America/Los_Angeles).
- Selected model: `external`, using the previously configured `claude-v4.6-sonnet` endpoint. Mode: `agent`; tracing off.
- Scope: only documents 2 and 4, the documents below 100 in the previous run. Both completed with status `ok`; no missing outputs; command sequence exited 0.
- Combined score for these two documents: **93.33 / 100**. This is not a new ten-document score; the other eight documents were not rerun.

## Comparison

| Document | Format | Previous score at 047824a | New score | Output summary | Remaining findings |
|---|---|---:|---:|---|---|
| doc-002.txt | fs-listing | 13.33 | 86.67 | 6 products, 16 CVEs | Missed XZ Utils 5.6.0 |
| doc-004.txt | html | 80.00 | 100.00 | 2 products, 2 CVEs | None |

The prior libxml2 miss in document 2 and Apache Solr miss in document 4 are resolved in this run. Document 2 still misses XZ Utils. Scores use the assignment's 40% products, 40% CVEs, and 20% CWE weights. Reported counts do not imply every reported match is correct.

## Exact testing procedure

Checked the local Git revision and changes using WSL. Git status showed only the ten existing untracked input copies. The documents were already present in `input/items/`. The agent image rebuilt successfully; the running MCP and gateway services were reused, with Compose confirming healthy dependencies. Execution used Windows `wsl --exec bash -lc` with this Bash body:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-d4dc35c/items
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-002.txt doc-004.txt" 2>&1 | tee test-results/rerun-d4dc35c/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-d4dc35c/grade.json -v doc-002.txt doc-004.txt | tee test-results/rerun-d4dc35c/grade.log
cp output/run.json test-results/rerun-d4dc35c/run.json
cp output/items/doc-002.txt.json output/items/doc-004.txt.json test-results/rerun-d4dc35c/items/
```

The explicit IDs limited both processing and grading to these two documents. Verified successful agent completion and read the verbose grader results. No conformance probe, full-dataset evaluation, or code edits were performed. This is one real-model retest; model variability may affect comparisons.

## Evidence

- [Grader JSON](grade.json)
- [Verbose grading log](grade.log)
- [Agent run log](run.log)
- [Run metadata](run.json)
- [Document 2 output](items/doc-002.txt.json)
- [Document 4 output](items/doc-004.txt.json)

## Additional real-model batch: documents 10–15

Tested the same commit, `d4dc35c`, on October 21, 2026. Only documents 10–15 were processed in this additional run, with `AGENT_MODEL=external`, `MODE=agent`, and the same configured real-model endpoint. All six completed with status `ok`, no missing outputs, and exit code 0. Agent processing time was 28.34 seconds; log interval 22:04:18–22:04:46 UTC (15:04:18–15:04:46 America/Los_Angeles).

**Batch score: 94.44 / 100.** Overall components: products 0.8611, CVEs 1.0000, CWE 1.0000. This batch score is separate from the earlier documents 2 and 4 retest.

| Document | Format | Products reported | CVEs reported | Score / 100 | Grader findings |
|---|---|---:|---:|---:|---|
| doc-010.txt | version-commands | 5 | 35 | 100.00 | None |
| doc-011.txt | banners | 5 | 2 | 100.00 | Extra product public_project:public:10.0.0.1 |
| doc-012.txt | pip | 6 | 16 | 100.00 | Extra product ibm:packaging_utility:21.3 |
| doc-013.txt | fs-listing | 6 | 8 | 100.00 | None |
| doc-014.xml | nmap-xml | 4 | 1 | 86.67 | Missed MySQL 5.7.33; extra product mysql:mysql:5.7.33 |
| doc-015.xml | maven-pom | 4 | 0 | 50.00 | Missed Apache Commons Collections 4.0; extra product powertekpdus:smart_pom:4.0.0 |

Documents 13 and 15 have no applicable CVE/CWE grading component (`null` in JSON, `nan` in the text report). Their scores use the grader's available-component weighting; these missing components are not treated as zero. Each document in this batch has a distinct format, so the per-document scores above are the grader's corresponding single-document format scores. The overall score averages component metrics over eligible documents and is not simply the mean of the six displayed scores. Reported counts come from the agent and do not imply correct matches.

### Exact commands for this batch

The agent image rebuilt successfully and the existing healthy MCP/gateway stack was reused. The initial input-copy attempt assumed all six files ended in `.txt`; it stopped before any model execution because documents 14 and 15 are `.xml`. After verifying the filenames, the following Bash body was executed via Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
mkdir -p test-results/rerun-d4dc35c/docs-010-015/items
cp datasets/train/items/doc-01{0,1,2,3}.txt datasets/train/items/doc-01{4,5}.xml input/items/
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="doc-010.txt doc-011.txt doc-012.txt doc-013.txt doc-014.xml doc-015.xml" 2>&1 | tee test-results/rerun-d4dc35c/docs-010-015/run.log
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report test-results/rerun-d4dc35c/docs-010-015/grade.json -v doc-01{0,1,2,3}.txt doc-01{4,5}.xml | tee test-results/rerun-d4dc35c/docs-010-015/grade.log
cp output/run.json test-results/rerun-d4dc35c/docs-010-015/run.json
cp output/items/doc-01{0,1,2,3}.txt.json output/items/doc-01{4,5}.xml.json test-results/rerun-d4dc35c/docs-010-015/items/
```

Verified that the logged inputs matched the six requested documents, every item completed successfully, and the grader reported no missing outputs. No application code was changed and no other documents or conformance checks were run in this batch. Existing input files were retained; the explicit IDs restricted processing and grading.

### Additional evidence

- [Batch grader JSON](docs-010-015/grade.json)
- [Batch verbose grading log](docs-010-015/grade.log)
- [Batch agent log](docs-010-015/run.log)
- [Batch run metadata](docs-010-015/run.json)
- Output snapshots are preserved in `docs-010-015/items/`.
