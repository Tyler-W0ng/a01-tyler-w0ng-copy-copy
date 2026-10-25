"""The vulnerability knowledge MCP server (A01).

Replaces AgentLab's processing server. On startup it loads the five frozen
feeds in $VULNDB_FEEDS into an in-memory SQLite database (loader.py), then
answers questions about CVEs, CWEs, CAPEC, KEV and CPE over MCP.

The data is loaded *before* the HTTP server starts, so the healthcheck's
GET /health only succeeds once the server is answering - which is exactly
"healthy means ready" (handout section 2). The seven tools the autograder's
probe requires are here, plus a couple that help a model map names to CPE
products and list versions.

No vulnerability data is baked into this image; it all comes from /feeds.
"""

import json
import threading

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

import loader
import resolve
import version as vercmp

server = MCPServer(name="vulndb", version="1.0.0")

DB = None                      # set by loader.load() at startup
LOCK = threading.Lock()        # sqlite connection is shared across threads


def _q(sql: str, args=()) -> list:
    with LOCK:
        return DB.execute(sql, args).fetchall()


def _cwes_for(cve_id: str) -> list:
    return [r["cwe_id"] for r in
            _q("SELECT cwe_id FROM cve_cwe WHERE cve_id = ?", (cve_id,))]


@server.tool()
def db_info() -> dict:
    """When the data was built and which feeds it came from."""
    meta = {r["key"]: r["value"] for r in _q("SELECT key, value FROM meta")}
    counts = {
        "cves": _q("SELECT COUNT(*) c FROM cve")[0]["c"],
        "cpe_products": _q("SELECT COUNT(*) c FROM cpe_product")[0]["c"],
        "kev": _q("SELECT COUNT(*) c FROM kev")[0]["c"],
    }
    return {"snapshot": meta.get("snapshot"), "built_at": meta.get("snapshot"),
            "feeds": json.loads(meta.get("feeds", "[]")), "counts": counts}


@server.tool()
def get_cve(cve_id: str) -> dict:
    """Description, CVSS score, CWE id(s), and whether the CVE is in KEV."""
    rows = _q("SELECT * FROM cve WHERE id = ?", (cve_id.strip().upper(),))
    if not rows:
        return {"id": cve_id, "error": "no such CVE in the 2026 feed"}
    r = rows[0]
    return {"id": r["id"], "description": r["description"],
            "cvss": r["cvss"], "cvss_version": r["cvss_version"],
            "cwes": _cwes_for(r["id"]), "kev": bool(r["in_kev"])}


@server.tool()
def get_cwe(cwe_id: str) -> dict:
    """A CWE's name and description, and the CAPEC patterns related to it."""
    cid = cwe_id.strip().upper()
    if not cid.startswith("CWE-"):
        cid = "CWE-" + cid
    rows = _q("SELECT * FROM cwe WHERE id = ?", (cid,))
    if not rows:
        return {"id": cid, "error": "no such CWE"}
    r = rows[0]
    capecs = [x["capec_id"] for x in
              _q("SELECT capec_id FROM cwe_capec WHERE cwe_id = ?", (cid,))]
    return {"id": r["id"], "name": r["name"], "description": r["description"],
            "related_capec": capecs}


@server.tool()
def get_capec(capec_id: str) -> dict:
    """A CAPEC pattern's name and description, and the CWEs it targets."""
    cid = capec_id.strip().upper()
    if not cid.startswith("CAPEC-"):
        cid = "CAPEC-" + cid
    rows = _q("SELECT * FROM capec WHERE id = ?", (cid,))
    if not rows:
        return {"id": cid, "error": "no such CAPEC"}
    r = rows[0]
    cwes = [x["cwe_id"] for x in
            _q("SELECT cwe_id FROM capec_cwe WHERE capec_id = ?", (cid,))]
    return {"id": r["id"], "name": r["name"], "description": r["description"],
            "related_cwe": cwes}


@server.tool()
def get_kev(cve_id: str) -> dict:
    """The KEV catalog entry for a CVE, or that there is none."""
    cid = cve_id.strip().upper()
    rows = _q("SELECT * FROM kev WHERE cve_id = ?", (cid,))
    if not rows:
        return {"cve_id": cid, "in_kev": False}
    r = rows[0]
    return {"cve_id": r["cve_id"], "in_kev": True, "date_added": r["date_added"],
            "vendor": r["vendor"], "product": r["product"], "name": r["name"]}


def _candidates(query: str) -> list:
    """Ranked CPE vendor:product candidates matching `query` by name or title.

    Names that carry a 2026 CVE are ranked first and never dropped, so a query
    like "mysql" also surfaces its CVE-bearing siblings (oracle:mysql_server)
    rather than only oracle:mysql. Each candidate carries a `has_cves` flag.
    """
    q = query.strip().lower()
    like = f"%{q}%"
    cve_vp = {(r["vendor"], r["product"]) for r in _q(
        """SELECT vendor, product FROM cve_product
           WHERE product LIKE ? OR vendor LIKE ?""", (like, like))}
    rows = _q("""SELECT vendor, product, title FROM cpe_product
                 WHERE product LIKE ? OR vendor LIKE ? OR LOWER(title) LIKE ?
                 LIMIT 1000""", (like, like, like))
    title = {(r["vendor"], r["product"]): r["title"] for r in rows}
    cand = set(title) | cve_vp

    def score(vp):
        p = vp[1].lower()
        base = 0 if vp in cve_vp else 10          # CVE-bearing names first
        if p == q:
            return base
        if p.startswith(q) or q in p.split("_"):
            return base + 1
        if q in p:
            return base + 2
        return base + 3

    ranked = sorted(cand, key=score)[:40]
    return [{"vendor": v, "product": p, "title": title.get((v, p), p),
             "has_cves": (v, p) in cve_vp} for v, p in ranked]


@server.tool()
def search_products(query: str) -> dict:
    """CPE vendor:product candidates whose name or title matches `query`.

    A caller resolving a product needs the CVE-bearing siblings (e.g.
    oracle:mysql_server for "mysql") to union its CVEs across every name NVD
    files it under. Each candidate carries a `has_cves` flag.
    """
    return {"query": query, "candidates": _candidates(query)}


def _has_cves(vendor: str, product: str) -> bool:
    return bool(_q("SELECT 1 FROM cve_product WHERE vendor = ? AND product = ? LIMIT 1",
                   (vendor, product)))


@server.tool()
def resolve_name(name: str) -> dict:
    """Map a product / package / banner name to its CPE vendor:product identities.

    Strips sub-package suffixes (openssh-server -> openssh), applies a small
    table of structural naming facts (httpd -> apache:http_server, libssl ->
    openssl:openssl), searches the CPE dictionary and ranks by confidence,
    dropping look-alikes that match only on a generic word (so "zend engine"
    does not resolve to docker:engine). Returns the best product's identities
    (`aliases`), the table `seed`, and same-family `variants` a caller may
    adjudicate; each alias notes `has_cves`.
    """
    clean = resolve.clean_name(name)
    seed = resolve.table(name)
    cands = _candidates(clean)
    if not cands:
        # separators differ between package names and CPE products
        # ("commons-collections" vs "commons_collections"); retry flattened.
        alt = clean.replace("-", " ").replace("_", " ").replace(".", " ")
        if alt != clean:
            cands = _candidates(alt)
    primary = resolve.rank_pick(clean, cands)
    variants = resolve.variant_candidates(primary, cands)
    allv = sorted(primary | seed)
    return {"name": name,
            "aliases": [{"vendor": v, "product": p, "has_cves": _has_cves(v, p)}
                        for v, p in allv],
            "seed": [{"vendor": v, "product": p} for v, p in sorted(seed)],
            "variants": variants}


@server.tool()
def list_versions(vendor: str, product: str) -> dict:
    """Known versions of a product (only kept where a 2026 CVE applies)."""
    rows = _q("SELECT DISTINCT version FROM cpe_version WHERE vendor = ? AND product = ?",
              (vendor.strip().lower(), product.strip().lower()))
    return {"vendor": vendor, "product": product,
            "versions": sorted(r["version"] for r in rows)}


@server.tool()
def vulnerabilities_for(vendor: str, product: str, version: str) -> dict:
    """The 2026 CVEs that apply to an exact vendor/product/version.

    The version is normalised first (epoch, distro suffix, MariaDB marker), so
    a caller can pass a packaging version like "1:7.6p1-4ubuntu0.7" directly.
    """
    vendor, product = vendor.strip().lower(), product.strip().lower()
    version = vercmp.normalize(version)
    rows = _q("""SELECT cve_id, exact, v_start, start_incl, v_end, end_incl
                 FROM cve_match WHERE vendor = ? AND product = ?""",
              (vendor, product))
    hits = {}
    for r in rows:
        if vercmp.matches(version, r["exact"], r["v_start"], r["start_incl"],
                          r["v_end"], r["end_incl"]):
            hits.setdefault(r["cve_id"], None)
    cves = []
    for cid in sorted(hits):
        crow = _q("SELECT cvss, in_kev FROM cve WHERE id = ?", (cid,))
        cvss = crow[0]["cvss"] if crow else None
        kev = bool(crow[0]["in_kev"]) if crow else False
        cves.append({"id": cid, "cwes": _cwes_for(cid), "cvss": cvss, "kev": kev})
    return {"vendor": vendor, "product": product, "version": version, "cves": cves}


@server.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


if __name__ == "__main__":
    # Load the feeds BEFORE serving, so the port only opens once we are ready:
    # the healthcheck gets connection-refused during the load (tolerated by
    # the 300s start_period) and 200 afterwards.
    print("vulndb: loading feeds...", flush=True)
    DB = loader.load()
    print("vulndb: ready", flush=True)
    server.run("streamable-http", host="0.0.0.0", port=8000)
