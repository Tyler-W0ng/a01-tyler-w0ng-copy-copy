"""Deterministic extraction: a document's text -> [(name, version, evidence)].

This is the hardcoded half of the agent. Structured, tool-generated formats
(SBOMs, package lists) parse cleanly here and never need the model. Loose
text (banners, headers, scans) gets a conservative regex pass; genuinely
free-form notes fall through with little, and the graph then asks the model.

Each candidate is {"name", "version", "evidence"}. We do not resolve CPEs or
look up CVEs here - that is resolver.py and the MCP server.
"""

import json
import re

# A packaging suffix after '-': distro build metadata, not the upstream version.
_PKG_SUFFIX = re.compile(
    r"-(?:r\d+|\d+ubuntu[\w.]*|\d+\.el\d[\w.]*|\d+build\d+|\d+deb[\w.]*|\d+\+[\w.]*|\d+[\w.]*ubuntu[\w.]*)$")


def normalize_version(v: str) -> str:
    """Upstream version: drop a Debian epoch and a distro packaging suffix."""
    v = v.strip()
    if re.match(r"^\d+:", v):            # epoch, e.g. "1:7.6p1-4ubuntu0.7"
        v = v.split(":", 1)[1]
    v = _PKG_SUFFIX.sub("", v)            # "16.13.0-r4" -> "16.13.0"
    return v

# A product token followed by a dotted version: "nginx/1.10.3", "OpenSSH 7.6p1".
_NAME_VER = re.compile(
    r"([A-Za-z][A-Za-z0-9._+-]{1,40}?)[ /]v?(\d+\.\d+[A-Za-z0-9.+_-]*)")


def _clean_version(v: str) -> str:
    return v.strip().strip(".,;)")


def _cand(name, version, evidence):
    return {"name": name.strip(), "version": _clean_version(version),
            "evidence": evidence.strip()[:200]}


def _dedup(cands):
    seen, out = set(), []
    for c in cands:
        if not c["name"] or not c["version"]:
            continue
        key = (c["name"].lower(), c["version"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


# --- structured JSON formats ----------------------------------------------

def _parse_json(text):
    """SBOMs and lockfiles. Returns (candidates, recognised)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], False
    cands = []

    # CycloneDX / Syft: components[] or artifacts[] with name + version
    for key in ("components", "artifacts"):
        for c in (data.get(key) or []) if isinstance(data, dict) else []:
            if isinstance(c, dict) and c.get("name") and c.get("version"):
                cands.append(_cand(c["name"], str(c["version"]),
                                   f"{key}: {c['name']} {c['version']}"))

    # SPDX: packages[] with name + versionInfo
    if isinstance(data, dict):
        for p in data.get("packages") or []:
            if isinstance(p, dict) and p.get("name") and p.get("versionInfo"):
                cands.append(_cand(p["name"], str(p["versionInfo"]),
                                   f"package: {p['name']} {p['versionInfo']}"))

    # npm package-lock: packages{} or dependencies{}
    if isinstance(data, dict) and ("lockfileVersion" in data or "dependencies" in data):
        for path, meta in (data.get("packages") or {}).items():
            name = path.split("node_modules/")[-1]
            if name and isinstance(meta, dict) and meta.get("version"):
                cands.append(_cand(name, str(meta["version"]), f"npm: {name}"))
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                cands.append(_cand(name, str(meta["version"]), f"npm: {name}"))

    return _dedup(cands), bool(cands)


# --- line-oriented package listings ---------------------------------------

def _parse_lines(text):
    cands = []
    for line in text.splitlines():
        s = line.strip()
        # dpkg -l : "ii  name  version  arch  description"
        m = re.match(r"[a-z]{2,3}\s+(\S+)\s+(\S+)\s+\S+", line)
        if m and line[:2] in ("ii", "rc", "hi"):
            cands.append(_cand(m.group(1).split(":")[0], m.group(2), s))
            continue
        # pip freeze : "name==1.2.3"
        m = re.match(r"([A-Za-z0-9._-]+)==([0-9][\w.]*)", s)
        if m:
            cands.append(_cand(m.group(1), m.group(2), s))
            continue
        # apk info -vv / generic "name-1.2.3-r0"
        m = re.match(r"([a-z0-9][a-z0-9._+-]*?)-(\d[\w.]*(?:-r\d+)?)\s*$", s)
        if m:
            cands.append(_cand(m.group(1), m.group(2), s))
    return _dedup(cands)


# --- loose text: banners, headers, scans, version commands ----------------

# tokens the "name version" regex captures that are never a product
_STOP = {"http", "https", "date", "content", "x", "ver", "version", "nmap",
         "api", "lucene", "uptime", "pid", "release", "host", "status",
         "ports", "name", "cluster", "node-", "protocol", "server", "connection"}


def _parse_text(text):
    cands = []
    for line in text.splitlines():
        for name, ver in _NAME_VER.findall(line):
            if name.lower() in _STOP:
                continue
            cands.append(_cand(name, ver, line.strip()))
    return _dedup(cands)


def detect(text):
    """A coarse family label, for logging and the messy/structured decision."""
    head = text.lstrip()[:1]
    if head == "{":
        return "json"
    if head == "<":
        return "xml"
    return "text"


def extract(text):
    """Return (fmt, candidates, structured)."""
    fmt = detect(text)

    if fmt == "json":
        cands, ok = _parse_json(text)
        if ok:
            return "json", cands, True

    line_cands = _parse_lines(text)
    if line_cands:
        return fmt, line_cands, True

    return fmt, _parse_text(text), False
