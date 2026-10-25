"""Name -> CPE vendor:product resolution, on the server side.

This is the naming logic the `resolve_name` tool exposes: strip sub-package
suffixes, apply a small table of structural naming facts, and rank search
candidates by confidence. It holds only naming facts (no vulnerability data),
so a model can ask the server to map a package/banner name to CPE identities
instead of the agent carrying that map.
"""

import re

# name (lowercased) -> set of (vendor, product) CPE identities.
#
# Deliberately small: ONLY structural naming facts that search cannot recover
# - where the name shares no word with the CPE product or its title, or where
# NVD files one product under several vendors. Products whose name matches
# their CPE product are not listed; the ranked search handles those.
ALIASES = {
    "nginx": {("nginx", "nginx"), ("f5", "nginx"), ("f5", "nginx_open_source")},
    "apache": {("apache", "http_server")},
    "apache2": {("apache", "http_server")},
    "httpd": {("apache", "http_server")},
    "apache httpd": {("apache", "http_server")},
    "microsoft-iis": {("microsoft", "internet_information_services")},
    "microsoft iis": {("microsoft", "internet_information_services")},
    "iis": {("microsoft", "internet_information_services")},
    "libssl": {("openssl", "openssl")},
    "libssl1.1": {("openssl", "openssl")},
    "libssl3": {("openssl", "openssl")},
    "liblzma": {("tukaani", "xz"), ("xz_project", "xz")},
    "libcurl": {("haxx", "curl"), ("curl", "curl")},
    "node": {("nodejs", "node.js")},
    "mysql": {("oracle", "mysql")},
    "mysqld": {("oracle", "mysql")},
    "python3-django": {("djangoproject", "django")},
}

# Words too generic to resolve a product on their own: "zend engine" must not
# win docker:engine, nor "7-zip" win info-zip:zip, on a single shared token.
GENERIC = {
    "engine", "server", "client", "core", "common", "base", "tools", "agent",
    "manager", "broker", "zip", "teams", "ms", "proxy", "router", "controller",
    "plugin", "module", "framework", "library", "service", "daemon", "utils",
    "db", "sdk", "cli",
}

_SUBPKG = re.compile(
    r"-(lib|libs|server|client|clients|common|dev|devel|bin|doc|docs|data|"
    r"core|utils|util|tools|mod|module|agent)$")


def clean_name(name: str) -> str:
    n = name.strip().lower()
    cleaned = _SUBPKG.sub("", n)
    return cleaned or n


def table(name: str) -> set:
    n = name.strip().lower()
    return ALIASES.get(n) or ALIASES.get(clean_name(n)) or set()


def _tokens(s: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


def _title_tokens(title) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", (title or "").lower()) if t}


def rank_pick(name: str, candidates: list) -> set:
    """From search candidates, pick the best product's identities.

    Accept an exact or normalised product-name match, a shared distinctive
    word, or (for a multi-word name) a title match. A match on only a generic
    word (engine, zip, server, ...) is treated as a look-alike and rejected
    unless the vendor also matches. Returns the (vendor, product) pairs sharing
    the best product name, or empty.
    """
    if not candidates:
        return set()
    q = name.strip().lower()
    qnorm = re.sub(r"[^a-z0-9]", "", q)
    qtokens = _tokens(name)

    scored = []
    for c in candidates:
        p = c["product"].lower()
        vendor = c["vendor"].lower()
        ptokens = set(p.split("_"))
        pnorm = re.sub(r"[^a-z0-9]", "", p)
        if p == q:
            s = 0
        elif vendor in qtokens and p in qtokens:
            s = 0
        elif pnorm == qnorm and qnorm:
            s = 1
        else:
            shared = qtokens & ptokens
            if shared and (shared - GENERIC or vendor in qtokens):
                s = 2 if (p in qtokens or q in ptokens) else 3
            elif len(qtokens) >= 2 and qtokens <= _title_tokens(c.get("title")):
                s = 4
            else:
                continue
        scored.append((s, c))

    if not scored:
        return set()
    strong = {(c["vendor"].lower(), c["product"].lower())
              for s, c in scored if s <= 1}
    if strong:
        return strong
    best_s = min(s for s, _ in scored)
    best_product = min(c["product"].lower() for s, c in scored if s == best_s)
    return {(c["vendor"].lower(), c["product"].lower())
            for c in candidates if c["product"].lower() == best_product}


def variant_candidates(primary: set, candidates: list) -> list:
    """Same-base-family search hits not already in `primary`, for a caller to
    adjudicate: "mysql" also appears as "mysql_server", "nginx" as
    "nginx_open_source". We surface every hit whose slug extends a primary slug
    by one or more tokens; the caller decides which are the same software."""
    if not primary:
        return []
    bases = [p.split("_") for (_v, p) in primary]
    out, seen = [], set()
    for c in candidates:
        vp = (c["vendor"].lower(), c["product"].lower())
        if vp in primary or vp in seen:
            continue
        ptoks = vp[1].split("_")
        if any(len(ptoks) > len(b) and ptoks[:len(b)] == b for b in bases):
            seen.add(vp)
            out.append({"vendor": vp[0], "product": vp[1],
                        "title": c.get("title", "")})
        if len(out) >= 12:
            break
    return out
