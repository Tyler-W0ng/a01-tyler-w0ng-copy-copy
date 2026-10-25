"""Deterministic extraction: a document's text -> [(name, version, evidence)].

This is the hardcoded half of the agent. Structured, tool-generated formats
(SBOMs, package lists) parse cleanly here and never need the model. Loose
text (banners, headers, scans) gets a conservative regex pass; genuinely
free-form notes fall through with little, and the graph then asks the model.

Each candidate is {"name", "version", "evidence"}. We do not resolve CPEs or
look up CVEs here - that is the MCP server (resolve_name, vulnerabilities_for).
"""

import json
import re
import xml.etree.ElementTree as ET


def _ln(tag: str) -> str:
    """XML local name, stripping any namespace."""
    return tag.rsplit("}", 1)[-1]


def _cpe_vp(cpe: str):
    """(vendor, product) from a CPE 2.2 URI or 2.3 string, or None."""
    cpe = (cpe or "").strip()
    if not cpe.startswith("cpe:"):
        return None
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[1] == "2.3":
        return (parts[3].lower(), parts[4].lower())
    if len(parts) >= 4 and parts[1].startswith("/"):   # cpe:/a:vendor:product:...
        return (parts[2].lower(), parts[3].lower())
    return None


# Generic reverse-DNS prefixes in a Maven groupId, which do not name the product
# (org.apache.struts -> "apache struts"; the vendor token like "apache" is kept).
_GENERIC_GROUP = {"com", "org", "io", "net", "edu", "gov", "me", "dev", "www",
                  "software"}


def _purl_hint(purl):
    """A resolution hint from a Package URL's namespace.

    For Maven, the groupId names the project better than the artifactId:
    `pkg:maven/org.apache.struts/struts2-core` -> "apache struts", which search
    resolves to apache:struts (the artifact name "struts2-core" does not). Other
    purl types carry a distro/ecosystem namespace that does not help a CPE
    lookup, so we skip them and let the plain name resolve.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:maven/"):
        return None
    group = purl[len("pkg:maven/"):].split("/", 1)[0].split("@", 1)[0]
    toks = [t for t in group.split(".") if t and t not in _GENERIC_GROUP]
    return " ".join(toks) if toks else None

# A packaging suffix after '-': distro build metadata, not the upstream version.
_PKG_SUFFIX = re.compile(
    r"-(?:r\d+|\d+ubuntu[\w.]*|\d+\.el\d[\w.]*|\d+build\d+|\d+deb[\w.]*|\d+\+[\w.]*|\d+[\w.]*ubuntu[\w.]*)$")


def normalize_version(v: str) -> str:
    """Upstream version: drop a Debian epoch and a distro packaging suffix."""
    v = v.strip()
    # MariaDB answers the MySQL protocol as "5.5.5-<real>-MariaDB-<pkg>"; the
    # leading 5.5.5 is a MySQL-compat marker and the real version is the middle.
    m = re.search(r"(?:5\.5\.5-)?(\d+\.\d+\.\d+)-mariadb", v, re.I)
    if m:
        return m.group(1)
    if re.match(r"^\d+:", v):            # epoch, e.g. "1:7.6p1-4ubuntu0.7"
        v = v.split(":", 1)[1]
    v = re.sub(r"[.+~]dfsg.*$", "", v)   # Debian repack marker: "1.2.12.dfsg" -> "1.2.12"
    v = _PKG_SUFFIX.sub("", v)            # "16.13.0-r4" -> "16.13.0"
    return v

# A product token followed by a dotted version: "nginx/1.10.3", "OpenSSH 7.6p1",
# "OpenSSH_7.2p2" (underscore separator in SSH banners).
_NAME_VER = re.compile(
    r"([A-Za-z][A-Za-z0-9._+-]{1,40}?)[ /_]v?(\d+\.\d+[A-Za-z0-9.+_-]*)")


def _clean_version(v: str) -> str:
    return v.strip().strip(".,;)")


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_private_ip(v: str) -> bool:
    """A private/reserved IPv4 address - a scan target, never a product version.
    Restricted to internal ranges so a real four-part version like 4.9.0.1
    (a public range) is NOT mistaken for an address."""
    if not _IPV4.match(v):
        return False
    o = [int(x) for x in v.split(".")]
    if any(x > 255 for x in o):
        return False
    return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31)
            or (o[0] == 192 and o[1] == 168) or o[0] == 127
            or (o[0] == 169 and o[1] == 254))


def _valid_version(v: str) -> bool:
    """A plausible software version: contains a digit and is not an internal IP.
    Drops junk the loose/model extractors invent from scan IPs, CIDR bases and
    words like 'Ubuntu' - which would otherwise become products (and, since
    search now ranks CVE-bearing names first, could pull in a high-CVE
    look-alike). Public four-part versions (4.9.0.1) are kept."""
    v = v.strip()
    if not any(ch.isdigit() for ch in v):
        return False
    if _is_private_ip(v):
        return False
    return True


def _cand(name, version, evidence):
    return {"name": name.strip(), "version": _clean_version(version),
            "evidence": evidence.strip()[:200]}


def _dedup(cands):
    seen, out = set(), []
    for c in cands:
        if not c["name"] or not c["version"] or not _valid_version(c["version"]):
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
                cand = _cand(c["name"], str(c["version"]),
                             f"{key}: {c['name']} {c['version']}")
                hint = _purl_hint(c.get("purl"))
                if hint:
                    cand["hint"] = hint          # resolve falls back to this
                cands.append(cand)

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

# RPM package arch suffixes, to recognise "rpm -qa" lines (name-version-release.arch)
_RPM_ARCH = re.compile(r"\.(x86_64|noarch|i686|i386|aarch64|armv7hl|s390x|ppc64le)$")


def _parse_lines(text):
    cands = []
    for line in text.splitlines():
        s = line.strip()
        # dpkg -l : "ii  name  version  arch  description"
        m = re.match(r"[a-z]{2,3}\s+(\S+)\s+(\S+)\s+\S+", line)
        if m and line[:2] in ("ii", "rc", "hi"):
            cands.append(_cand(m.group(1).split(":")[0], m.group(2), s))
            continue
        # rpm -qa : "name-version-release.arch" (e.g. sqlite-libs-3.22.0-11.el8.x86_64).
        # Strip the last '-' segment (release.arch), then split name/version at
        # the first '-<digit>' so names and versions that contain '-' survive
        # (net-snmp-5.7.3, runc-1.0.0-rc6).
        if _RPM_ARCH.search(s):
            nv = s.rpartition("-")[0]
            m = re.match(r"^(.+?)-(\d[\w.+~-]*)$", nv)
            if m:
                cands.append(_cand(m.group(1), m.group(2), s))
                continue
        # pip freeze : "name==1.2.3"
        m = re.match(r"([A-Za-z0-9._-]+)==([0-9][\w.]*)", s)
        if m:
            cands.append(_cand(m.group(1), m.group(2), s))
            continue
        # apt version pins : "name=version" (apt-get install, Dockerfiles).
        # Require a dotted, digit-led value so ENV assignments
        # ("DEBIAN_FRONTEND=noninteractive") and flags are not mistaken for it.
        matched_pin = False
        for name, val in re.findall(r"([A-Za-z][A-Za-z0-9.+_-]*)=([^\s\\]+)", s):
            if name.isupper() or name.lower() in _STOP:
                continue
            core = val.split(":", 1)[-1]               # drop a Debian epoch
            if core[:1].isdigit() and "." in core.split("-")[0]:
                cands.append(_cand(name, val, s))
                matched_pin = True
        if matched_pin:
            continue
        # apk info -vv / generic "name-1.2.3-r0"
        m = re.match(r"([a-z0-9][a-z0-9._+-]*?)-(\d[\w.]*(?:-r\d+)?)\s*$", s)
        if m:
            cands.append(_cand(m.group(1), m.group(2), s))
    return _dedup(cands)


# --- loose text: banners, headers, scans, version commands ----------------

# tokens the "name version" regex captures that are never a product. Includes
# the prose words that leak out of tool-summary lines ("scanned in 346.53
# seconds" -> name "in"; "Redis key-value store 5.0.7" -> name "store").
_STOP = {"http", "https", "date", "content", "x", "ver", "version", "nmap",
         "api", "lucene", "uptime", "pid", "release", "host", "status",
         "ports", "name", "cluster", "node-", "protocol", "server", "connection",
         "in", "at", "up", "of", "store", "value"}


# Shared-library files in a filesystem listing: "liblzma.so.5.6.0" -> (liblzma, 5.6.0).
# The dotted .so suffix is not matched by _NAME_VER, so handle it explicitly.
_SO_FILE = re.compile(r"(lib[a-z0-9_+-]+)\.so\.(\d+(?:\.\d+)+)")

# A versioned path segment in a filesystem listing, where name and version are
# joined by '-' (so _NAME_VER's space/slash separator misses them):
# ".../Jinja2-3.1.2.dist-info", ".../phpMyAdmin-4.8.1-all-languages",
# ".../wordpress-5.4.2.zip".
_PATH_NV = re.compile(r"/([A-Za-z][A-Za-z0-9._+]*?)-(\d+(?:\.\d+)+)")


def _parse_text(text):
    cands = []
    for line in text.splitlines():
        for name, ver in _SO_FILE.findall(line):
            cands.append(_cand(name, ver, line.strip()))
        for name, ver in _PATH_NV.findall(line):
            cands.append(_cand(name, ver, line.strip()))
        for name, ver in _NAME_VER.findall(line):
            if name.lower() in _STOP:
                continue
            cands.append(_cand(name, ver, line.strip()))
    return _dedup(cands)


# --- structured XML formats -----------------------------------------------

def _parse_nmap_xml(text):
    """nmap -oX: <service product=.. version=..> with an embedded <cpe>, which
    gives the exact NVD vendor:product - better than any name guess."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    cands = []
    for svc in root.iter():
        if _ln(svc.tag) != "service":
            continue
        product, ver = svc.get("product"), svc.get("version")
        if not ver:
            continue
        vp = next((_cpe_vp(ch.text) for ch in svc if _ln(ch.tag) == "cpe"), None)
        name = product or (vp[1] if vp else None)
        if not name:
            continue
        c = _cand(name, ver, f"{name} {ver}")
        if vp:
            c["vp"] = vp          # resolve uses this directly, skipping search
        cands.append(c)
    return _dedup(cands)


def _parse_maven_pom(text):
    """Maven pom.xml: the <dependencies> artifactId + version (resolving
    ${property} refs). Skips test scope and the schema's modelVersion."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    props = {}
    for el in root.iter():
        if _ln(el.tag) == "properties":
            for p in el:
                props[_ln(p.tag)] = (p.text or "").strip()
    cands = []
    for dep in root.iter():
        if _ln(dep.tag) != "dependency":
            continue
        aid = ver = scope = None
        for ch in dep:
            t = _ln(ch.tag)
            if t == "artifactId":
                aid = (ch.text or "").strip()
            elif t == "version":
                ver = (ch.text or "").strip()
            elif t == "scope":
                scope = (ch.text or "").strip()
        if scope == "test":
            continue
        if ver and ver.startswith("${") and ver.endswith("}"):
            ver = props.get(ver[2:-1], "")
        if aid and ver and ver[:1].isdigit():
            cands.append(_cand(aid, ver, f"{aid} {ver}"))
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

    if fmt == "xml":
        low = text.lower()
        if "nmaprun" in low or "<service" in low:
            cands = _parse_nmap_xml(text)
            if cands:
                return "nmap-xml", cands, True
        if "modelversion" in low or "maven.apache.org/pom" in low:
            cands = _parse_maven_pom(text)
            if cands:
                return "maven-pom", cands, True

    # A pure package dump (dpkg/rpm/pip/apk) is fully handled by code. But a
    # document can MIX a package excerpt with scan output or prose (host
    # reports), so only skip the model when the package lines account for most
    # of the content; otherwise combine them and let the model read the rest.
    content = [l for l in text.splitlines()
               if l.strip() and not l.strip().startswith("#")]
    line_cands = _parse_lines(text)
    if line_cands and len(line_cands) >= 0.5 * max(1, len(content)):
        return fmt, line_cands, True

    return fmt, _dedup(line_cands + _parse_text(text)), False
