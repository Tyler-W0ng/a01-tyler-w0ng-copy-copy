"""Version comparison for CPE applicability matching.

NVD states which versions a CVE covers as an exact version, or as a range
(versionStart*/versionEnd*), or as "every version" (* with no bounds). To
decide membership we need to order version strings like 2.4.29 < 2.4.58 and
7.2 < 7.2p2, which plain string comparison gets wrong.

We tokenise a version into numeric and alphabetic runs and compare the lists:
numeric parts compare as integers, and a version that is a prefix of another
is the smaller one (7.2 < 7.2p2, 2.4 < 2.4.1).
"""

import re

_TOKEN = re.compile(r"\d+|[a-z]+")

_PKG_SUFFIX = re.compile(
    r"-(?:r\d+|\d+ubuntu[\w.]*|\d+\.el\d[\w.]*|\d+build\d+|\d+deb[\w.]*|\d+\+[\w.]*)$")


def normalize(v: str) -> str:
    """Upstream version from a packaging string: drop a Debian epoch and a
    distro packaging suffix, and read MariaDB's MySQL-protocol marker. So a
    caller can pass "1:7.6p1-4ubuntu0.7" or "5.5.5-10.1.48-MariaDB-..." and
    still match. Idempotent on an already-clean version."""
    v = (v or "").strip()
    m = re.search(r"(?:5\.5\.5-)?(\d+\.\d+\.\d+)-mariadb", v, re.I)
    if m:
        return m.group(1)
    v = re.sub(r"^\d+:", "", v)           # epoch, e.g. "1:7.6p1-4ubuntu0.7"
    v = re.sub(r"[.+~]dfsg.*$", "", v)    # Debian repack marker
    return _PKG_SUFFIX.sub("", v)


def _key(version: str) -> list:
    parts = []
    for tok in _TOKEN.findall((version or "").lower()):
        if tok.isdigit():
            parts.append((1, int(tok)))   # numeric: ranks above an alpha run
        else:
            parts.append((0, tok))         # alpha, e.g. the "p" in 7.2p2
    return parts


def matches(version: str, exact, v_start, start_incl, v_end, end_incl) -> bool:
    """Does `version` satisfy one CPE match entry?"""
    v = _key(version)
    if not v:
        return False
    if exact:
        return v == _key(exact)
    if v_start:
        s = _key(v_start)
        if (v < s) or (v == s and not start_incl):
            return False
    if v_end:
        e = _key(v_end)
        if (v > e) or (v == e and not end_incl):
            return False
    return True
