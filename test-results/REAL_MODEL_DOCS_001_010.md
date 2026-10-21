# Real-model test: documents 1–10

- Date: October 21, 2026 (America/Los_Angeles).
- Model: `external`, configured as `claude-v4.6-sonnet`; mode: `agent`.
- All 10 documents completed with status `ok`; no missing outputs.
- Agent processing time: 110.23 seconds, excluding build/startup.
- Overall score: **73.00 / 100**, compared with **41.00 / 100** for the mock-model run (+32 points).
- Overall components: products 0.625, CVEs 0.800, CWE 0.800.

## Exact testing procedure

### Environment and configuration

- Executed in WSL Bash from Windows using `wsl --exec bash -lc`, in `/mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy`.
- Docker Compose stack was already running. The run log confirms healthy gateway, MCP, and mock service containers before the agent started. No `make up` was needed for this run.
- Selected `AGENT_MODEL=external` and `MODE=agent`. The agent sent model requests through `http://gateway:4000/v1`; `.env` configured `EXTERNAL_MODEL=claude-v4.6-sonnet` and `EXTERNAL_LITELLM_MODEL=openai/claude-v4.6-sonnet` via the configured AWS API Gateway endpoint. This records the configured model name, not an independently verified provider model identity. No API keys are included in this report.
- The mock service remained running as a stack dependency, but the selected model for this run was `external`, not `mock-model`.
- MCP endpoint: `http://mcp:8000/mcp`. Its advertised tools were `db_info`, `get_capec`, `get_cve`, `get_cwe`, `get_kev`, `list_versions`, `search_products`, and `vulnerabilities_for`.
- Tracing was off; run metadata listed no optional capabilities.
- The training answer key records feed snapshot `2026-10-12`. The test used the existing MCP service; its database was not rebuilt or independently revalidated during this run.

### Input preparation

The ten training inputs were already copied during the preceding mock-model test using:

```bash
mkdir -p input/items report
cp datasets/train/items/doc-00{1,2,3,4,5,6,7,8,9}.txt datasets/train/items/doc-010.txt input/items/
```

Other inputs were not deleted. The explicit `ITEM` list restricted execution to documents 1–10, and the grader received the same ten document IDs. The answer key was used by the grader after execution.

### Commands executed for the real-model run

The following is the Bash command body passed to `wsl --exec bash -lc`, formatted across lines for readability:

```bash
set -e
cd /mnt/c/Users/tyguy/Documents/Projects/temp/a01-tyler-w0ng-copy-copy
set -o pipefail

AGENT_MODEL=external make run MODE=agent ITEM="doc-001.txt doc-002.txt doc-003.txt doc-004.txt doc-005.txt doc-006.txt doc-007.txt doc-008.txt doc-009.txt doc-010.txt" 2>&1 | tee report/real-model-docs-001-010-run.log

python3 grader/grade.py --expected datasets/train/expected.json --outputs output/items --report report/real-model-docs-001-010.json -v doc-00{1,2,3,4,5,6,7,8,9}.txt doc-010.txt | tee report/real-model-docs-001-010-grade.log
```

`make run` rebuilt the agent image successfully and invoked `docker compose run --rm agent` with the ten IDs. The existing MCP and gateway containers were reused. `set -e` and `pipefail` made command or pipeline failures stop the sequence rather than silently proceeding to grading.

### Validation and evidence handling

- Ran one real-model batch for this report; document 1 had also been tested separately beforehand. No application-code changes were made between the mock baseline and this batch.
- Checked the run log and metadata: only the ten requested IDs were processed, all finished with status `ok`, and the shell sequence exited with code 0.
- Graded the generated JSON outputs using the repository's `grader/grade.py`, the training key `datasets/train/expected.json`, verbose diagnostics, and a machine-readable JSON report. The grader reported no missing outputs.
- Agent log interval: 20:43:25–20:45:15 UTC on October 21, 2026 (13:43:25–13:45:15 America/Los_Angeles). Metadata completion timestamp: `2026-10-21T20:45:15.553551+00:00`. Recorded processing duration: 110.23 seconds.
- Calculated per-document scores as `100 * (0.4 * products + 0.4 * cves + 0.2 * cwe)` from the grader metrics. The reported overall score of 73.00 comes directly from the grader.
- Copied `output/run.json` to `report/real-model-docs-001-010-run.json` to preserve this run's metadata. Later copied the Markdown, both logs, grading JSON, and metadata snapshot to `test-results/` because `report/*` is Git-ignored.
- Did not run `make eval`, `make check`, the MCP conformance probe, the remaining training documents, or hidden evaluation data. API spend, request counts, package versions, image digests, and the Git commit were not captured.

## Per-document results

| Document | Format | Output summary | Products | CVEs | CWE | Weighted score / 100 |
|---|---|---|---:|---:|---:|---:|
| doc-001.txt | http-headers | 6 product(s), 42 CVE(s) | 1.0000 | 1.0000 | 1.0000 | 100.00 |
| doc-002.txt | fs-listing | 5 product(s), 13 CVE(s) | 0.6667 | 1.0000 | 1.0000 | 86.67 |
| doc-003.txt | nmap-normal | 6 product(s), 27 CVE(s) | 0.3333 | 1.0000 | 1.0000 | 73.33 |
| doc-004.txt | html | 3 product(s), 1 CVE(s) | 0.5000 | 1.0000 | 1.0000 | 80.00 |
| doc-005.txt | nmap-normal | 7 product(s), 37 CVE(s) | 1.0000 | 1.0000 | 1.0000 | 100.00 |
| doc-006.txt | rpm-qa | 21 product(s), 31 CVE(s) | 0.0000 | 0.0000 | 0.0000 | 0.00 |
| doc-007.txt | rpm-qa | 14 product(s), 8 CVE(s) | 0.0000 | 0.0000 | 0.0000 | 0.00 |
| doc-008.txt | whatweb | 3 product(s), 66 CVE(s) | 1.0000 | 1.0000 | 1.0000 | 100.00 |
| doc-009.txt | apk-info | 5 product(s), 2 CVE(s) | 1.0000 | 1.0000 | 1.0000 | 100.00 |
| doc-010.txt | version-commands | 6 product(s), 35 CVE(s) | 0.7500 | 1.0000 | 1.0000 | 90.00 |

Scores use the handout weights: products 40%, CVEs 40%, CWE 20%. Component values range from 0 to 1. Reported product/CVE counts are not counts of correct matches.

## Main findings

- Documents 6 and 7 scored zero: RPM release/architecture suffixes were reported as software versions, and Node.js was missed.
- Other misses include XZ Utils, Webmin, MongoDB, Apache Solr, and curl; the grader details below identify incorrect product matches.
- This covers only ten training documents. Runtime success is separate from answer accuracy. No conformance probe was run.

## Grader findings

### doc-001.txt

- extra product eclipse:hudson:1.395

### doc-002.txt

- missed XZ Utils 5.6.0

### doc-003.txt

- missed Webmin 1.920
- missed MongoDB 4.4.6
- extra product loxone:miniserver_gen_1:1.920
- extra product anynines:mongodb:4.4.6
- extra product cisco:ons_15454_optical_transport_platform:5.17.5
- extra product apple:installer:244.83
- extra product gentoo:webmin:1.920

### doc-004.txt

- missed Apache Solr 7.7.2
- extra product alejandro_garza:apachesolr_autocomplete:7.7.2
- extra product apache:lucene.net:7.7.2

### doc-005.txt

- extra product oracle:mysql:5.5.5-10.5.15-MariaDB
- extra product cisco:ons_15454_optical_transport_platform:5.15.3
- extra product apple:installer:194.24

### doc-006.txt

- missed SQLite 3.22.0 (reported version '11.el8.x86_64')
- missed Git 2.34.1 (reported version '10.el8.x86_64')
- missed OpenSSH 7.4p1 (reported version '3.el7.x86_64')
- missed Node.js 10.19.0
- missed runc 1.0.0-rc6 (reported version '17.el8.x86_64')
- extra product suse:basesystem_module:7.el7.centos.x86_64
- extra product sqlite:sqlite:11.el8.x86_64
- extra product git_project:git:10.el8.x86_64
- extra product joyent:node.js:16.el8.x86_64
- extra product linuxfoundation:runc:17.el8.x86_64
- extra product openbsd:openssh:3.el7.x86_64

### doc-007.txt

- missed NTP 4.2.8p10 (reported version '18.el7.x86_64')
- missed Net-SNMP 5.7.3 (reported version '4.el7.x86_64')
- missed Squid 5.2 (reported version '10.el7.x86_64')
- missed Node.js 10.19.0
- extra product ntp:ntp:18.el7.x86_64
- extra product net-snmp:net-snmp:4.el7.x86_64
- extra product squid-cache:squid:10.el7.x86_64
- extra product joyent:node.js:3.el8.x86_64

### doc-008.txt

- No grader findings.

### doc-009.txt

- extra product openssl:openssl:1.34.1

### doc-010.txt

- missed curl 7.68.0
- extra product curl:curl:7.68.0
- extra product haxx:libcurl:7.68.0

## Evidence

- [Grader JSON](real-model-docs-001-010.json)
- [Run log](real-model-docs-001-010-run.log)
- [Verbose grader log](real-model-docs-001-010-grade.log)
- [Run metadata snapshot](real-model-docs-001-010-run.json)
- Output files: `../output/items/doc-001.txt.json` through `doc-010.txt.json`; these replace the prior mock-model outputs and may be overwritten by future runs.

