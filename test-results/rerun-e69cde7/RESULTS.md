# Seventh iteration: six-document targeted retest

- Commit: `e69cde7` (`7th iteration`); checked before execution and again after grading.
- Model: `external`, same configured real-model endpoint; mode `agent`; tracing off.
- All six agent items completed with status `ok`; no missing outputs. Agent processing time: 64.94 seconds, excluding rebuild/startup.
- Selected-subset score: **90.11 / 100**. This is not a full-set score.

## Comparison

| Document | Previous score | New score | Output summary |
|---|---:|---:|---|
| doc-030.txt | 76.00 | 100.00 | 9 product(s), 49 CVE(s) |
| doc-037.txt | 92.00 | 92.00 | 8 product(s), 24 CVE(s) |
| doc-040.txt | 50.00 | 50.00 | 5 product(s), 1033 CVE(s) |
| doc-042.json | 92.00 | 92.00 | 9 product(s), 49 CVE(s) |
| doc-045.txt | 51.83 | 86.67 | 4 product(s), 35 CVE(s) |
| doc-047.json | 90.00 | 90.00 | 7 product(s), 27 CVE(s) |

Document 30 now scores 100. Document 45 improved because its CVE recall increased, but GNU C Library remains missing. Documents 37, 40, 42, 45, and 47 remain below 100. Document 40 reported 1,033 CVEs; this is an agent output count, not a count of correct graded CVEs, and its remaining missed product still limits the score. No application-code fixes were made during this test.

Scores use weights 40% products, 40% CVEs, 20% CWE, renormalized over non-null components. The overall grader score averages components over eligible documents, so it need not equal the mean of the document scores. Some extras are tolerated. Other documents were not rerun.

## Grader findings

### doc-030.txt

- extra product uxgroupllc:cast_to_tv:192.168.7.160
- extra product public_project:public:10.0.0.1
- extra product jorisvm:jvm_gutenberg_rich_text_icons:11.0.19

### doc-037.txt

- missed Microsoft IIS 10.0
- extra product apache:http_server:10.0
- extra product pretix:double_opt_in_step:97.31
- extra product microsoft:iis:10.0
- 4 reported CVE(s) do not apply

### doc-040.txt

- missed NTP 4.2.6p5
- extra product uxgroupllc:cast_to_tv:10.17.148.5
- extra product ntpd_driver_project:ntpd_driver:4.2.6p5

### doc-042.json

- missed Apache Struts 2.3.31

### doc-045.txt

- missed GNU C Library 2.31
- extra product bordeaux-metropole:at_internet_piano_analytics:3.2.1
- extra product thelibrarian:the_librarian:192.168.18.0

### doc-047.json

- missed Express 4.18.2
- extra product express:express:4.18.2

## Exact testing procedure

Git status showed only existing untracked input copies. Changes since `d2f2c1a` included agent graph, model integration, resolver, MCP loader, and MCP server. Both agent and MCP images were explicitly rebuilt successfully before testing. `make up MODE=agent` recreated MCP, loaded the feeds, waited for health, and synchronized existing gateway key policies. The gateway was restarted to refresh service connections. The agent run then waited for healthy dependencies.

Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
dest=test-results/rerun-e69cde7
mkdir -p "$dest/items"
ids=(doc-030.txt doc-037.txt doc-040.txt doc-042.json doc-045.txt doc-047.json)
printf "%s\n" "${ids[@]}" > "$dest/input-ids.txt"
git rev-parse HEAD > "$dest/commit.txt"
set -o pipefail
docker compose build agent mcp 2>&1 | tee "$dest/build.log"
make up MODE=agent 2>&1 | tee "$dest/startup.log"
docker compose restart gateway 2>&1 | tee -a "$dest/startup.log"
AGENT_MODEL=external make run MODE=agent ITEM="${ids[*]}" 2>&1 | tee "$dest/run.log"
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report "$dest/grade.json" -v "${ids[@]}" | tee "$dest/grade.log"
cp output/run.json "$dest/run.json"
for id in "${ids[@]}"; do cp "output/items/$id.json" "$dest/items/"; done
```

The agent completed successfully, but WSL lost its working-directory reference: `make` emitted a `getcwd` warning, and the first grading attempt failed with `FileNotFoundError` in Python's import path resolution. The command sequence stopped before snapshot copying. No extra model run was performed. Re-entered the directory in a fresh WSL command and ran grading/snapshot preservation successfully with this body:

```bash
set -e
cd /
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
dest=test-results/rerun-e69cde7
ids=(doc-030.txt doc-037.txt doc-040.txt doc-042.json doc-045.txt doc-047.json)
set -o pipefail
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report "$dest/grade.json" -v "${ids[@]}" 2>&1 | tee "$dest/grade.log"
cp output/run.json "$dest/run.json"
for id in "${ids[@]}"; do cp "output/items/$id.json" "$dest/items/"; done
git rev-parse HEAD
```

Verified all six requested IDs, successful statuses, no missing outputs, six preserved output snapshots, and unchanged commit after grading. Grading recovery exited 0. No conformance probe or full-dataset run was performed. Per-document API request counts and cost were not collected; deterministic paths can bypass model requests.

## Evidence

- [Grader JSON](grade.json), [verbose grader log](grade.log)
- [Run log](run.log), [run metadata](run.json)
- [Build log](build.log), [startup log](startup.log)
- [Input manifest](input-ids.txt), [commit](commit.txt)
- Six output snapshots in `items/`.

## Remaining documents in 30–50 (15-document batch)

- Commit: `e69cde7`; application/service files had no changes since the preceding six-document run.
- Excluded documents 30, 37, 40, 42, 45, and 47 exactly as requested. None were rerun.
- Selected model `external`, same real-model endpoint; mode `agent`; tracing off.
- All 15 requested documents completed with status `ok`, no missing outputs, and exit code 0.
- Agent processing time: 99.41 seconds, excluding build/startup. Full completion timestamp is in the batch run metadata.
- Batch score: **98.13 / 100**. Products 0.9533, CVEs 1.0000, CWE 1.0000.

| Document | Format | Score / 100 | Output summary |
|---|---|---:|---|
| doc-031.txt | html | 100.00 | 5 product(s), 10 CVE(s) |
| doc-032.txt | analyst-notes | 100.00 | 0 product(s), 0 CVE(s) |
| doc-033.txt | nmap-normal | 100.00 | 4 product(s), 22 CVE(s) |
| doc-034.json | syft-json | 100.00 | 5 product(s), 33 CVE(s) |
| doc-035.txt | dpkg-list | 100.00 | 7 product(s), 18 CVE(s) |
| doc-036.txt | banners | 100.00 | 4 product(s), 27 CVE(s) |
| doc-038.txt | analyst-notes | 80.00 | 3 product(s), 8 CVE(s) |
| doc-039.txt | http-headers | 92.00 | 5 product(s), 51 CVE(s) |
| doc-041.txt | ps-aux | 100.00 | 0 product(s), 0 CVE(s) |
| doc-043.txt | nmap-grepable | 100.00 | 2 product(s), 4 CVE(s) |
| doc-044.json | cyclonedx-json | 100.00 | 5 product(s), 24 CVE(s) |
| doc-046.txt | http-headers | 100.00 | 2 product(s), 5 CVE(s) |
| doc-048.xml | nmap-xml | 100.00 | 4 product(s), 43 CVE(s) |
| doc-049.json | cyclonedx-json | 100.00 | 12 product(s), 47 CVE(s) |
| doc-050.txt | dpkg-list | 100.00 | 8 product(s), 9 CVE(s) |

Documents 38 and 39 are the only documents below 100 in this batch; both miss Microsoft IIS. Both previously scored 100 in the full run at `94817e8`, so these are observed regressions. Per-document scores use available-component weights; null components are excluded. The overall score averages components over eligible documents. Reported output counts are not correctness counts; some 100-point documents have tolerated extras.

### Grader findings

- **doc-033.txt**: extra product amilia:store:5.0.7
- **doc-033.txt**: extra product pretix:double_opt_in_step:346.53
- **doc-033.txt**: 4 reported CVE(s) do not apply
- **doc-034.json**: extra product openssl:openssl:1.34.1
- **doc-034.json**: 1 reported CVE(s) do not apply
- **doc-036.txt**: extra product uxgroupllc:cast_to_tv:172.22.47.14
- **doc-036.txt**: 4 reported CVE(s) do not apply
- **doc-038.txt**: missed Microsoft IIS 7.5
- **doc-038.txt**: extra product bordeaux-metropole:at_internet_piano_analytics:10.19.0
- **doc-038.txt**: extra product microsoft:iis:7.5
- **doc-039.txt**: missed Microsoft IIS 10.0
- **doc-039.txt**: extra product microsoft:iis:10.0
- **doc-043.txt**: extra product pretix:double_opt_in_step:97.31
- **doc-044.json**: extra product openssl:openssl:1.34.1

### Exact testing procedure

Verified the local revision and checked application/service differences against `e69cde7`; none were present. Inspected the dataset filenames. All selected inputs were already copied. The agent image rebuilt successfully; the healthy MCP and gateway services from the preceding test were reused. Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
dest=test-results/rerun-e69cde7/remaining-030-050
mkdir -p "$dest/items"
ids=(doc-031.txt doc-032.txt doc-033.txt doc-034.json doc-035.txt doc-036.txt doc-038.txt doc-039.txt doc-041.txt doc-043.txt doc-044.json doc-046.txt doc-048.xml doc-049.json doc-050.txt)
printf "%s\n" "${ids[@]}" > "$dest/input-ids.txt"
git rev-parse HEAD > "$dest/commit.txt"
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="${ids[*]}" 2>&1 | tee "$dest/run.log"
cd /
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report "$dest/grade.json" -v "${ids[@]}" 2>&1 | tee "$dest/grade.log"
cp output/run.json "$dest/run.json"
for id in "${ids[@]}"; do cp "output/items/$id.json" "$dest/items/"; done
```

Re-entered the directory before grading to avoid the earlier WSL working-directory issue. Verified all 15 statuses, no missing outputs, all 15 output snapshots, and that the input manifest excludes the six previously tested documents. No application edits, conformance probe, or other inputs were included.

### Batch evidence

- [Grader JSON](remaining-030-050/grade.json), [verbose grading log](remaining-030-050/grade.log)
- [Run log](remaining-030-050/run.log), [run metadata](remaining-030-050/run.json)
- [Input manifest](remaining-030-050/input-ids.txt), [commit](remaining-030-050/commit.txt)
- Output snapshots: `remaining-030-050/items/`.
