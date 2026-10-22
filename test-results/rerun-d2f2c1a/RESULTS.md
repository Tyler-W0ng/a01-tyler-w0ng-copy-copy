# Sixth iteration: retest of seven documents below 100

- Commit: `d2f2c1a` (`6th iteration`). Changes since `94817e8`: `agent/app/graph.py` and `parsers.py`.
- Local date: October 21, 2026 (America/Los_Angeles). UTC completion timestamp is preserved in `run.json`.
- Model: `external`, same configured real-model endpoint; mode `agent`; tracing off.
- All seven documents completed with status `ok`; no missing outputs; command sequence exited 0.
- Processing time: 35.25 seconds, excluding build/startup.
- Selected-subset score: **82.29 / 100**. This is not comparable to the prior 50-document overall score because this batch contains only the previously underperforming documents.

## Comparison

| Document | Previous score | New score |
|---|---:|---:|
| doc-030.txt | 76.00 | 76.00 |
| doc-037.txt | 92.00 | 92.00 |
| doc-040.txt | 50.00 | 50.00 |
| doc-042.json | 92.00 | 92.00 |
| doc-045.txt | 51.83 | 51.83 |
| doc-047.json | 90.00 | 90.00 |
| doc-048.xml | 77.32 | 100.00 |

Document 48 now scores 100 and its MariaDB version/CVE misses are resolved. The other six remain below 100. Scores use component weights 40% products, 40% CVEs, 20% CWE, renormalized over non-null components. A format summary can differ from an individual-document score when its component averages use different eligible subsets. No other documents were rerun, so this is not a full regression check.

## Remaining findings

### doc-030.txt

- missed Apache ActiveMQ 5.18.2
- missed Net-SNMP 5.7.3
- missed Jenkins 2.441
- extra product public_project:public:10.0.0.1

### doc-037.txt

- missed Microsoft IIS 10.0
- extra product apache:http_server:10.0
- extra product microsoft:iis:10.0
- 4 reported CVE(s) do not apply

### doc-040.txt

- missed NTP 4.2.6p5
- extra product ntpd_driver_project:ntpd_driver:4.2.6p5
- extra product conectiva:linux:5.4.0-150-generic

### doc-042.json

- missed Apache Struts 2.3.31

### doc-045.txt

- missed GNU C Library 2.31
- extra product cisco:80-7111-01_for_the_unity-svrx255-1a:192.168.18.0
- missed 27 CVE(s): CVE-2026-21936, CVE-2026-21937, CVE-2026-21941, CVE-2026-21948, CVE-2026-21968, CVE-2026-21998 ...

### doc-047.json

- missed Express 4.18.2
- extra product express:express:4.18.2

## Exact testing procedure

Checked the local revision and status; only the existing training input copies were untracked. Rebuilt the agent image successfully and reused the healthy MCP and gateway services. The seven inputs were already present. Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
dest=test-results/rerun-d2f2c1a
mkdir -p "$dest/items"
ids=(doc-030.txt doc-037.txt doc-040.txt doc-042.json doc-045.txt doc-047.json doc-048.xml)
printf "%s\n" "${ids[@]}" > "$dest/input-ids.txt"
git rev-parse HEAD > "$dest/commit.txt"
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="${ids[*]}" 2>&1 | tee "$dest/run.log"
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report "$dest/grade.json" -v "${ids[@]}" | tee "$dest/grade.log"
cp output/run.json "$dest/run.json"
for id in "${ids[@]}"; do cp "output/items/$id.json" "$dest/items/"; done
```

Verified the seven logged IDs, successful completion, grader diagnostics, and preserved output snapshots. No application edits, conformance probe, or additional documents were included. This was one run with the real-model configuration; individual deterministic paths may bypass model requests. API request counts and spend were not collected.

## Evidence

- [Grader JSON](grade.json)
- [Verbose grading log](grade.log)
- [Run log](run.log)
- [Run metadata](run.json)
- [Input manifest](input-ids.txt)
- [Commit](commit.txt)
- Seven output snapshots: `items/`.
