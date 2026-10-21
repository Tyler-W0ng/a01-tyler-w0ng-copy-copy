#!/usr/bin/env python3
"""Score a run of the triage agent against a dataset's answer key.

    python3 grade.py --expected datasets/train/expected.json --outputs output/items
    python3 grade.py --expected ... --outputs ... --report report.json --verbose

Standard library only. Reads one <id>.json per document from --outputs (the
format is in the assignment handout) and compares it with expected.json.
Every document counts the same; within a document:

  products  share of the key's products you report: same CPE vendor:product
            (any of the product's CPE names) and the same version. You may
            report up to twice as many products as the key has (at least 2)
            at no cost; beyond that the share is scaled by allowance /
            reported.
            Ignored, reported or not: products the document shows without
            a version (the key's `ignored`), the OS and its base packages
            (`neutral_products`), software shown only in passing
            (`tolerated`).
  cves      share of the required CVEs of the products you found that you
            report under them. Up to twice as many CVEs as are required cost
            nothing; beyond that the share is scaled the same way. A
            product's `optional_cves` are neither required nor counted.
            Documents whose products have no CVEs are left out; finding none
            of a document's products that have CVEs scores 0.
  cwe       for each required CVE you report correctly, whether at least
            one CWE you give is one NVD or the CNA assigned (0 when you
            report no correct CVE in a document that has some).

The key covers the CVE years in its `cve_years` (CVE-2026-* only). Reported
CVEs from other years are ignored, neither right nor wrong.

    score = 100 * (0.40 products + 0.40 cves + 0.20 cwe)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

WEIGHTS = {"products": 0.40, "cves": 0.40, "cwe": 0.20}
ALLOWANCE = 2          # extra products and CVEs are free up to this many times the expected
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.I)
_TOKEN = re.compile(r"\d+|[a-z]+")


# --------------------------------------------------------------------------
# Reading an output
# --------------------------------------------------------------------------

def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _split_cpe(cpe: str) -> list[str]:
    return [_unescape(p) for p in re.split(r"(?<!\\):", cpe)]


def _field(v: Any) -> Optional[str]:
    return None if v in (None, "", "*", "-") else str(v)


def identify(p: dict) -> tuple[Optional[tuple[str, str]], Optional[str]]:
    """(vendor, product) and version of a reported product.

    From its CPE (2.3 string or 2.2 URI; the version is the CPE's version
    plus its update field, so `openssh:7.2:p2` is 7.2p2), or from explicit
    vendor/product/version fields. A `version` field fills in a CPE that
    has none.
    """
    vp, version = None, None
    cpe = p.get("cpe")
    if isinstance(cpe, list):
        cpe = cpe[0] if cpe else None
    if isinstance(cpe, str) and cpe.lower().startswith("cpe:"):
        parts = _split_cpe(cpe)
        if parts[1] == "2.3" and len(parts) >= 5:
            vp = parts[3].lower(), parts[4].lower()
            rest = parts[5:7]
        elif parts[1].startswith("/") and len(parts) >= 4:          # CPE 2.2 URI
            vp = parts[2].lower(), parts[3].lower()
            rest = parts[4:6]
        else:
            rest = []
        if rest and _field(rest[0]):
            update = _field(rest[1]) if len(rest) > 1 else None
            version = rest[0] + (update or "")
    if vp is None and p.get("vendor") and p.get("product"):
        vp = str(p["vendor"]).lower(), str(p["product"]).lower()
    return vp, version or _field(p.get("version"))


def _tokens(v: str) -> list:
    t = [int(x) if x.isdigit() else x for x in _TOKEN.findall(v.lower())]
    while t and t[-1] == 0:
        t.pop()
    return t


def same_version(reported: Optional[str], expected: str) -> bool:
    """Upstream versions compared leniently: 1:7.6p1-4ubuntu0.7, v7.6p1, 7.6.p1 and 7.6p1 agree."""
    if not reported:
        return False
    v = re.sub(r"^\d+:", "", reported.strip().lower())       # Debian epoch
    v = re.sub(r"^v(?=\d)", "", v)
    candidates = {v, v.split("+")[0]}
    if "-" in v:
        candidates.add(v.rsplit("-", 1)[0])                    # distribution revision
    want = _tokens(expected)
    return any(_tokens(c.replace("~", "-")) == want for c in candidates)


def reported_cves(p: dict) -> dict[str, set[str]]:
    """{CVE id: {CWE ids}} from a product's `cves`, however it is shaped."""
    out: dict[str, set[str]] = {}
    for c in p.get("cves") or []:
        if isinstance(c, str):
            cid, cwes = c, []
        elif isinstance(c, dict):
            cid = c.get("id") or c.get("cve") or c.get("cve_id") or ""
            cwes = c.get("cwes") or c.get("cwe") or []
            if isinstance(cwes, str):
                cwes = [cwes]
        else:
            continue
        m = CVE_RE.search(str(cid))
        if not m:
            continue
        ids = set()
        for w in cwes:
            if isinstance(w, dict):
                w = w.get("id", "")
            mw = CWE_RE.search(str(w))
            if mw:
                ids.add(f"CWE-{mw.group(1)}")
        out.setdefault(m.group(0).upper(), set()).update(ids)
    return out


# --------------------------------------------------------------------------
# One document
# --------------------------------------------------------------------------

def _mean(xs: list[float]) -> Optional[float]:
    return sum(xs) / len(xs) if xs else None


def lenient(found: int, expected: int, reported: int, minimum: int = 0) -> float:
    """Share found, scaled down only past the allowance for extras."""
    share = found / expected if expected else 1.0
    allowance = max(ALLOWANCE * expected, minimum)
    return share * min(1.0, allowance / reported) if reported > allowance else share


def score_document(expected: dict, output: Optional[dict], neutral: set[str],
                   cve_years: Optional[set[int]] = None) -> dict:
    truth = expected["products"]
    reported = [] if not output else [p for p in output.get("products") or [] if isinstance(p, dict)]
    failures: list[str] = []
    if output is None:
        failures.append("no output")
    elif output.get("status") == "error":
        failures.append(f"agent reported an error: {str(output.get('error'))[:120]}")

    aliases = [{tuple(c.split(":", 1)) for c in t["cpe"]} for t in truth]
    ignored = {tuple(c.split(":", 1)) for t in expected.get("ignored") or [] for c in t["cpe"]}
    tolerated = set(expected.get("tolerated") or [])

    # Match each key product to a reported one with the same name and version.
    matched: dict[int, dict] = {}
    extras: dict[tuple, dict] = {}
    for p in reported:
        vp, version = identify(p)
        if vp is None:
            failures.append(f"product without a CPE or vendor/product: {p.get('name')!r}")
            extras[("?", str(p.get("name")), version)] = p
            continue
        hit = next((ti for ti, t in enumerate(truth)
                    if vp in aliases[ti] and same_version(version, t["version"])), None)
        if hit is not None:
            if hit in matched:   # the same product again (another host): merge its CVEs
                matched[hit] = {"cves": (matched[hit].get("cves") or []) + (p.get("cves") or [])}
            else:
                matched[hit] = p
            continue
        known = any(vp in a for a in aliases)
        if not known and (vp in ignored or vp[1] in neutral or vp[1] in tolerated):
            continue
        extras.setdefault((vp[0], vp[1], version), p)

    m: dict[str, Optional[float]] = {}
    m["products"] = lenient(len(matched), len(truth), len(matched) + len(extras), minimum=ALLOWANCE)
    for ti, t in enumerate(truth):
        if ti not in matched:
            near = [k for k in extras if k[:2] in aliases[ti]]
            failures.append(f"missed {t['name']} {t['version']}" +
                            (f" (reported version {near[0][2]!r})" if near else ""))
    for key in extras:
        failures.append(f"extra product {':'.join(str(k) for k in key if k)}")

    # CVEs, over the products found.
    required: dict[str, list[str]] = {}
    optional: set[str] = set()
    got: dict[str, set[str]] = defaultdict(set)
    for ti, p in matched.items():
        required.update(truth[ti]["cves"])
        optional.update(truth[ti].get("optional_cves") or [])
        for cid, cwes in reported_cves(p).items():
            if not cve_years or int(cid[4:8]) in cve_years:
                got[cid] |= cwes
    correct = [c for c in got if c in required]
    counted = [c for c in got if c not in optional]
    has_cves = any(t["cves"] for t in truth)
    if not has_cves:
        m["cves"] = m["cwe"] = None
    elif not required:          # none of the products with CVEs was found
        m["cves"] = m["cwe"] = 0.0
    else:
        m["cves"] = lenient(len(correct), len(required), len(counted))
        m["cwe"] = _mean([1.0 if got[c] & set(required[c]) else 0.0 for c in correct if required[c]])
        if m["cwe"] is None:
            m["cwe"] = 0.0 if not correct else None
    missed = sorted(set(required) - set(got))
    if missed:
        failures.append(f"missed {len(missed)} CVE(s): {', '.join(missed[:6])}" +
                        (" ..." if len(missed) > 6 else ""))
    extra = len(counted) - len(correct)
    if extra:
        over = len(counted) > ALLOWANCE * len(required)
        failures.append(f"{extra} reported CVE(s) do not apply" +
                        (f" (penalized: {len(counted)} reported, {ALLOWANCE * len(required)} allowed)"
                         if over and required else ""))
    wrong_cwe = [c for c in correct if required[c] and not got[c] & set(required[c])]
    if wrong_cwe:
        failures.append(f"no correct CWE for {', '.join(wrong_cwe[:6])}" +
                        (" ..." if len(wrong_cwe) > 6 else ""))

    return {"metrics": m, "failures": failures,
            "counts": {"expected_products": len(truth), "found_products": len(matched),
                       "extra_products": len(extras), "required_cves": len(required),
                       "reported_cves": len(got), "correct_cves": len(correct)}}


# --------------------------------------------------------------------------
# A dataset
# --------------------------------------------------------------------------

def load_output(outputs: Path, doc_id: str) -> Optional[dict]:
    path = outputs / f"{doc_id}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {"status": "error", "error": f"unreadable output: {exc}", "products": []}
    return data if isinstance(data, dict) else {"status": "error", "error": "output is not an object"}


def score_dataset(expected: dict, outputs: Path, only: Optional[set[str]] = None) -> dict:
    neutral = set(expected.get("neutral_products") or [])
    cve_years = set(expected.get("cve_years") or []) or None
    docs = {}
    for doc_id, exp in sorted(expected["items"].items()):
        if only and doc_id not in only:
            continue
        scored = score_document(exp, load_output(outputs, doc_id), neutral, cve_years)
        docs[doc_id] = {"format": exp["format"], **scored}

    def aggregate(ids: list[str]) -> dict:
        agg = {k: _mean([docs[i]["metrics"][k] for i in ids if docs[i]["metrics"][k] is not None])
               for k in WEIGHTS}
        # A metric no document applies to (a format whose products have no
        # CVEs) leaves the others to share its weight.
        used = {k: w for k, w in WEIGHTS.items() if agg[k] is not None}
        score = 100 * sum(w * agg[k] for k, w in used.items()) / (sum(used.values()) or 1)
        return {"documents": len(ids), **{k: (round(v, 4) if v is not None else None) for k, v in agg.items()},
                "score": round(score, 2)}

    by_format = defaultdict(list)
    for doc_id, d in docs.items():
        by_format[d["format"]].append(doc_id)
    missing = [d for d in docs if "no output" in docs[d]["failures"]]
    return {"dataset": expected.get("dataset"), "database": expected.get("database"),
            "weights": WEIGHTS, "overall": aggregate(list(docs)),
            "by_format": {f: aggregate(ids) for f, ids in sorted(by_format.items())},
            "missing_outputs": missing, "documents": docs}


def print_report(report: dict, verbose: bool) -> None:
    o = report["overall"]
    cols = list(WEIGHTS)

    def row(name: str, a: dict) -> str:
        cells = " ".join(f"{(a[k] if a[k] is not None else float('nan')):>9.3f}" for k in cols)
        return f"{name:<20} {a['documents']:>4} {cells} {a['score']:>7.2f}"

    print()
    print(f"{'format':<20} {'docs':>4} " + " ".join(f"{k:>9}" for k in cols) + f" {'score':>7}")
    print("-" * (20 + 5 + 10 * len(cols) + 8))
    for f, a in report["by_format"].items():
        print(row(f, a))
    print("-" * (20 + 5 + 10 * len(cols) + 8))
    print(row("OVERALL", o))
    print()
    if report["missing_outputs"]:
        print(f"  no output for {len(report['missing_outputs'])} document(s): "
              f"{', '.join(report['missing_outputs'][:10])}{' ...' if len(report['missing_outputs']) > 10 else ''}")
    if verbose:
        for doc_id, d in report["documents"].items():
            if d["failures"]:
                print(f"  {doc_id} ({d['format']}):")
                for f in d["failures"]:
                    print(f"      - {f}")
    print(f"  SCORE {o['score']:.2f} / 100")
    print()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Score triage outputs against an answer key.")
    ap.add_argument("--expected", type=Path, required=True)
    ap.add_argument("--outputs", type=Path, required=True, help="directory of <id>.json outputs")
    ap.add_argument("--report", type=Path, help="write the full report as JSON here")
    ap.add_argument("--verbose", "-v", action="store_true", help="list what went wrong, per document")
    ap.add_argument("ids", nargs="*", help="score only these documents")
    args = ap.parse_args(argv)
    expected = json.loads(args.expected.read_text())
    report = score_dataset(expected, args.outputs, set(args.ids) or None)
    print_report(report, args.verbose)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
