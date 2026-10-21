#!/usr/bin/env python3
"""Conformance probe for a student's vulnerability MCP server.

    python mcp_probe.py http://mcp:8000/mcp            # from inside the stack's network
    python mcp_probe.py http://mcp:8000/mcp --json probe.json

Needs the `mcp` package (2.x). Locally, run it in any image that has it,
such as the template's agent image (handout section 6); the autograder runs
it from a container of its own.

The handout fixes a minimum interface - seven tool names and the facts their
answers must contain - and leaves everything else (extra tools, schemas,
storage) to the student. Each check asks a question whose answer the
course's feed snapshot fixes, and looks for the answer as text *anywhere* in
the tool's result (case-insensitive), so any reasonable JSON shape passes.
Every CVE it asks about is a 2026 one, the assignment's scope. What is
checked:

  db_info              answers, and says when the data was built
  get_cve              CVE-2026-24061 (GNU inetutils telnetd): CVSS 9.8, CWE-88, KEV
  get_cwe              CWE-79: its name mentions cross-site scripting / web page
  get_capec            CAPEC-66: SQL injection, related to CWE-89
  get_kev              CVE-2026-24061 is in KEV; CVE-2026-35387 is not
  search_products      "openssh" finds openbsd:openssh
  vulnerabilities_for  apache:http_server 2.4.49 includes CVE-2026-29167 and
                       CVE-2026-29168, and 2.4.67 does not include
                       CVE-2026-29168 (fixed there); openbsd:openssh 7.2p2
                       includes CVE-2026-35387
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from mcp import Client

REQUIRED = ["db_info", "get_cve", "get_cwe", "get_capec", "get_kev",
            "search_products", "vulnerabilities_for"]

# (tool, arguments, what must appear in the answer, what must not)
CHECKS = [
    ("db_info", {}, [], []),
    ("get_cve", {"cve_id": "CVE-2026-24061"}, ["9.8", "CWE-88", "kev"], []),
    ("get_cwe", {"cwe_id": "CWE-79"}, ["cross-site scripting|web page generation"], []),
    ("get_capec", {"capec_id": "CAPEC-66"}, ["sql injection", "CWE-89"], []),
    ("get_kev", {"cve_id": "CVE-2026-24061"}, ["true|2026-01-26|inetutils"], []),
    ("get_kev", {"cve_id": "CVE-2026-35387"}, [], ["2026-01-26"]),
    ("search_products", {"query": "openssh"}, ["openbsd", "openssh"], []),
    ("vulnerabilities_for", {"vendor": "apache", "product": "http_server", "version": "2.4.49"},
     ["CVE-2026-29167", "CVE-2026-29168"], []),
    ("vulnerabilities_for", {"vendor": "apache", "product": "http_server", "version": "2.4.67"},
     [], ["CVE-2026-29168"]),
    ("vulnerabilities_for", {"vendor": "openbsd", "product": "openssh", "version": "7.2p2"},
     ["CVE-2026-35387"], []),
]


def _text(result) -> str:
    parts = [getattr(b, "text", "") for b in result.content]
    if result.structured_content is not None:
        parts.append(json.dumps(result.structured_content))
    return "\n".join(parts).lower()


async def probe(url: str) -> dict:
    out = {"url": url, "tools": [], "missing": [], "checks": [], "passed": 0, "total": 0}
    async with Client(url, read_timeout_seconds=60) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        out["tools"] = sorted(tools)
        out["missing"] = [t for t in REQUIRED if t not in tools]
        for name, args, must, must_not in CHECKS:
            check = {"tool": name, "args": args, "ok": False, "why": ""}
            if name not in tools:
                check["why"] = "tool missing"
            else:
                try:
                    text = _text(await client.call_tool(name, args))
                    absent = [m for m in must if not any(alt.lower() in text for alt in m.split("|"))]
                    present = [m for m in must_not if m.lower() in text]
                    check["ok"] = not absent and not present
                    check["why"] = ("missing " + ", ".join(absent) if absent else "") + \
                                   (" contains " + ", ".join(present) if present else "")
                except Exception as exc:                     # noqa: BLE001
                    check["why"] = f"{type(exc).__name__}: {exc}"[:200]
            out["checks"].append(check)
    out["total"] = len(out["checks"])
    out["passed"] = sum(c["ok"] for c in out["checks"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--json", help="also write the result here")
    args = ap.parse_args()
    try:
        result = asyncio.run(probe(args.url))
    except Exception as exc:                                 # noqa: BLE001
        result = {"url": args.url, "error": f"{type(exc).__name__}: {exc}", "passed": 0,
                  "total": len(CHECKS), "missing": REQUIRED, "checks": []}
    if result.get("error"):
        print(f"cannot talk to {args.url}: {result['error']}")
    else:
        print(f"tools: {', '.join(result['tools'])}")
        if result["missing"]:
            print(f"MISSING required tools: {', '.join(result['missing'])}")
        for c in result["checks"]:
            print(f"  {'ok  ' if c['ok'] else 'FAIL'}  {c['tool']}({json.dumps(c['args'])}) {c['why']}")
    print(f"MCP conformance: {result['passed']}/{result['total']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=1)
    return 0 if result["passed"] == result["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
