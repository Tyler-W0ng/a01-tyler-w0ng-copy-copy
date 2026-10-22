# Full training evaluation: documents 1–50

- Commit: `94817e826c01dec894bedfdb0468e98a12183585` (`5th iteration`).
- Date: October 21, 2026. Agent log interval: 23:55:09–23:58:39 UTC (16:55:09–16:58:39 America/Los_Angeles).
- Model selection: `external`; configured model `claude-v4.6-sonnet` and provider mapping `openai/claude-v4.6-sonnet`, using the existing approved endpoint. Model identity was not independently verified.
- Mode: `agent`; tracing off. Agent model gateway: `http://gateway:4000/v1`; MCP: `http://mcp:8000/mcp`.
- All 50 documents completed with status `ok`; no missing outputs; command sequence exited 0.
- Processing time: 210.51 seconds, excluding image build/startup.
- Overall score: **96.97 / 100**. Components: products 0.9533, CVEs 0.971, CWE 1.
- Documents scoring 100: **43/50**. Below 100: **7**.

## Documents below 100

| Document | Format | Score / 100 |
|---|---|---:|
| doc-030.txt | banners | 76.00 |
| doc-037.txt | nmap-grepable | 92.00 |
| doc-040.txt | banners | 50.00 |
| doc-042.json | syft-json | 92.00 |
| doc-045.txt | analyst-notes | 51.83 |
| doc-047.json | npm-lock | 90.00 |
| doc-048.xml | nmap-xml | 77.32 |

Document 23 now scores 100. Document 30 regressed from its previous 100-point batch result; this run misses Apache ActiveMQ, Net-SNMP, and Jenkins. This is one full training-set run, not a hidden-data evaluation. Code changes and real-model variability can both affect comparisons.

## All document scores

| Document | Format | Score / 100 | Agent output summary |
|---|---|---:|---|
| doc-001.txt | http-headers | 100.00 | 6 product(s), 42 CVE(s) |
| doc-002.txt | fs-listing | 100.00 | 7 product(s), 17 CVE(s) |
| doc-003.txt | nmap-normal | 100.00 | 4 product(s), 27 CVE(s) |
| doc-004.txt | html | 100.00 | 2 product(s), 2 CVE(s) |
| doc-005.txt | nmap-normal | 100.00 | 6 product(s), 37 CVE(s) |
| doc-006.txt | rpm-qa | 100.00 | 10 product(s), 32 CVE(s) |
| doc-007.txt | rpm-qa | 100.00 | 7 product(s), 13 CVE(s) |
| doc-008.txt | whatweb | 100.00 | 3 product(s), 66 CVE(s) |
| doc-009.txt | apk-info | 100.00 | 4 product(s), 2 CVE(s) |
| doc-010.txt | version-commands | 100.00 | 6 product(s), 35 CVE(s) |
| doc-011.txt | banners | 100.00 | 5 product(s), 2 CVE(s) |
| doc-012.txt | pip | 100.00 | 6 product(s), 16 CVE(s) |
| doc-013.txt | fs-listing | 100.00 | 7 product(s), 8 CVE(s) |
| doc-014.xml | nmap-xml | 100.00 | 3 product(s), 1 CVE(s) |
| doc-015.xml | maven-pom | 100.00 | 2 product(s), 0 CVE(s) |
| doc-016.txt | windows-inventory | 100.00 | 5 product(s), 22 CVE(s) |
| doc-017.txt | version-commands | 100.00 | 3 product(s), 13 CVE(s) |
| doc-018.txt | ps-aux | 100.00 | 0 product(s), 0 CVE(s) |
| doc-019.txt | whatweb | 100.00 | 5 product(s), 68 CVE(s) |
| doc-020.txt | host-report | 100.00 | 5 product(s), 12 CVE(s) |
| doc-021.txt | version-commands | 100.00 | 4 product(s), 5 CVE(s) |
| doc-022.txt | dockerfile | 100.00 | 2 product(s), 21 CVE(s) |
| doc-023.txt | dockerfile | 100.00 | 6 product(s), 25 CVE(s) |
| doc-024.txt | html | 100.00 | 3 product(s), 25 CVE(s) |
| doc-025.txt | fs-listing | 100.00 | 7 product(s), 5 CVE(s) |
| doc-026.json | spdx-json | 100.00 | 8 product(s), 52 CVE(s) |
| doc-027.txt | analyst-notes | 100.00 | 1 product(s), 0 CVE(s) |
| doc-028.json | spdx-json | 100.00 | 5 product(s), 12 CVE(s) |
| doc-029.txt | host-report | 100.00 | 4 product(s), 28 CVE(s) |
| doc-030.txt | banners | 76.00 | 4 product(s), 2 CVE(s) |
| doc-031.txt | html | 100.00 | 5 product(s), 10 CVE(s) |
| doc-032.txt | analyst-notes | 100.00 | 0 product(s), 0 CVE(s) |
| doc-033.txt | nmap-normal | 100.00 | 3 product(s), 22 CVE(s) |
| doc-034.json | syft-json | 100.00 | 5 product(s), 33 CVE(s) |
| doc-035.txt | dpkg-list | 100.00 | 8 product(s), 18 CVE(s) |
| doc-036.txt | banners | 100.00 | 3 product(s), 27 CVE(s) |
| doc-037.txt | nmap-grepable | 92.00 | 7 product(s), 24 CVE(s) |
| doc-038.txt | analyst-notes | 100.00 | 2 product(s), 8 CVE(s) |
| doc-039.txt | http-headers | 100.00 | 5 product(s), 51 CVE(s) |
| doc-040.txt | banners | 50.00 | 4 product(s), 1 CVE(s) |
| doc-041.txt | ps-aux | 100.00 | 0 product(s), 0 CVE(s) |
| doc-042.json | syft-json | 92.00 | 9 product(s), 49 CVE(s) |
| doc-043.txt | nmap-grepable | 100.00 | 1 product(s), 4 CVE(s) |
| doc-044.json | cyclonedx-json | 100.00 | 5 product(s), 24 CVE(s) |
| doc-045.txt | analyst-notes | 51.83 | 3 product(s), 4 CVE(s) |
| doc-046.txt | http-headers | 100.00 | 2 product(s), 5 CVE(s) |
| doc-047.json | npm-lock | 90.00 | 7 product(s), 27 CVE(s) |
| doc-048.xml | nmap-xml | 77.32 | 4 product(s), 30 CVE(s) |
| doc-049.json | cyclonedx-json | 100.00 | 12 product(s), 47 CVE(s) |
| doc-050.txt | dpkg-list | 100.00 | 8 product(s), 9 CVE(s) |

Per-document scores are calculated from grader metrics using weights 0.4 products, 0.4 CVEs, and 0.2 CWE, renormalized over non-null components. Overall scoring averages each component over eligible documents and is not necessarily the mean of document scores. Null CVE/CWE components mean not applicable, not zero. Reported counts are agent totals, not counts of correct matches. Some 100-point documents have tolerated extras.

## Grader findings

### doc-001.txt

- extra product eclipse:hudson:1.395

### doc-003.txt

- extra product ca:advantage_data_transport:5.17.5

### doc-005.txt

- extra product oracle:mysql:5.5.5-10.5.15-MariaDB
- extra product ca:advantage_data_transport:5.15.3

### doc-006.txt

- 4 reported CVE(s) do not apply

### doc-009.txt

- extra product openssl:openssl:1.34.1

### doc-010.txt

- extra product goforandroid:go_bookmark_widget:1.17.10

### doc-011.txt

- extra product public_project:public:10.0.0.1

### doc-012.txt

- extra product ibm:packaging_utility:21.3

### doc-016.txt

- extra product info-zip_project:zip:21.07
- extra product nuance:visual_c++_runtime_for_dragon_naturallyspeaking:14.29.30133

### doc-021.txt

- 1 reported CVE(s) do not apply

### doc-023.txt

- 1 reported CVE(s) do not apply

### doc-026.json

- 4 reported CVE(s) do not apply

### doc-027.txt

- extra product cisco:80-7111-01_for_the_unity-svrx255-1a:10.23.13.0

### doc-028.json

- extra product openssl:openssl:1.34.1

### doc-030.txt

- missed Apache ActiveMQ 5.18.2
- missed Net-SNMP 5.7.3
- missed Jenkins 2.441
- extra product public_project:public:10.0.0.1

### doc-033.txt

- extra product nopcommerce:store:5.0.7
- 4 reported CVE(s) do not apply

### doc-034.json

- extra product openssl:openssl:1.34.1
- 1 reported CVE(s) do not apply

### doc-036.txt

- 4 reported CVE(s) do not apply

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

### doc-044.json

- extra product openssl:openssl:1.34.1

### doc-045.txt

- missed GNU C Library 2.31
- extra product cisco:80-7111-01_for_the_unity-svrx255-1a:192.168.18.0
- missed 27 CVE(s): CVE-2026-21936, CVE-2026-21937, CVE-2026-21941, CVE-2026-21948, CVE-2026-21968, CVE-2026-21998 ...

### doc-047.json

- missed Express 4.18.2
- extra product express:express:4.18.2

### doc-048.xml

- missed MariaDB 10.1.48 (reported version '5.5.5-10.1.48-MariaDB')
- extra product mariadb:mariadb:5.5.5-10.1.48-MariaDB
- missed 13 CVE(s): CVE-2026-1642, CVE-2026-27651, CVE-2026-27654, CVE-2026-27784, CVE-2026-28753, CVE-2026-32647 ...

## Exact testing procedure

Verified the local Git revision and status; only existing input copies were untracked before the run. Compared application/service changes since `177a54f`: only `agent/app/parsers.py` and `resolver.py` changed. The agent image rebuilt successfully. The existing MCP and gateway services were reused and Compose confirmed healthy dependencies. No application code was edited during testing.

Enumerated the training dataset, verified exactly 50 inputs, copied all of them to `input/items/`, and passed their exact filenames explicitly to the runner and grader. This includes TXT, XML, and JSON inputs; the preserved input manifest lists every ID. Other existing inputs were not deleted. The answer key was used by the grader after the run.

Executed this Bash body through Windows `wsl --exec bash -lc`:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
dest=test-results/full-94817e8
mkdir -p "$dest/items"
ids=()
for path in datasets/train/items/doc-*; do
  id=${path##*/}
  ids+=("$id")
  cp "$path" input/items/
done
test "${#ids[@]}" -eq 50
printf "%s\n" "${ids[@]}" > "$dest/input-ids.txt"
git rev-parse HEAD > "$dest/commit.txt"
set -o pipefail
AGENT_MODEL=external make run MODE=agent ITEM="${ids[*]}" 2>&1 | tee "$dest/run.log"
python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report "$dest/grade.json" -v "${ids[@]}" | tee "$dest/grade.log"
cp output/run.json "$dest/run.json"
for id in "${ids[@]}"; do cp "output/items/$id.json" "$dest/items/"; done
```

Validated the requested input list, all 50 successful item statuses, grader results, and preserved output count. The training key records feed snapshot `2026-10-12`; MCP was reused, not independently reloaded or probed. No `make eval`, `make check`, or MCP conformance probe was run. Per-document API call counts and spend were not collected; deterministic paths may bypass calls even with the external model selected.

## Evidence

- [Grader JSON](grade.json)
- [Verbose grader log](grade.log)
- [Agent run log](run.log)
- [Run metadata](run.json)
- [Input ID manifest](input-ids.txt)
- [Full Git commit](commit.txt)
- All 50 output snapshots: `items/`.
