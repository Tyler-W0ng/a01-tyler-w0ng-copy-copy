"""Load the five frozen feeds in $VULNDB_FEEDS into an in-memory SQLite DB.

Everything is stdlib. The database lives in memory because the container's
root filesystem is read-only (see compose.yaml). We keep:

  * every 2026 CVE: description, CVSS, CWE ids, KEV flag;
  * every CVE's `vulnerable` CPE match (vendor/product + version bounds);
  * every CPE product's name + title (so any product resolves), and the
    versions only of products that a 2026 CVE mentions;
  * CWE and CAPEC names/descriptions and the links between them;
  * the KEV catalog.
"""

import gzip
import io
import json
import os
import sqlite3
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

FEEDS = Path(os.environ.get("VULNDB_FEEDS", "/feeds"))


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE cve(id TEXT PRIMARY KEY, description TEXT,
                         cvss REAL, cvss_version TEXT, in_kev INTEGER DEFAULT 0);
        CREATE TABLE cve_cwe(cve_id TEXT, cwe_id TEXT);
        CREATE TABLE cve_match(cve_id TEXT, vendor TEXT, product TEXT,
                               exact TEXT, v_start TEXT, start_incl INTEGER,
                               v_end TEXT, end_incl INTEGER);
        CREATE TABLE cpe_product(vendor TEXT, product TEXT, title TEXT,
                                 PRIMARY KEY(vendor, product));
        CREATE TABLE cpe_version(vendor TEXT, product TEXT, version TEXT);
        CREATE TABLE cwe(id TEXT PRIMARY KEY, name TEXT, description TEXT);
        CREATE TABLE cwe_capec(cwe_id TEXT, capec_id TEXT);
        CREATE TABLE capec(id TEXT PRIMARY KEY, name TEXT, description TEXT);
        CREATE TABLE capec_cwe(capec_id TEXT, cwe_id TEXT);
        CREATE TABLE kev(cve_id TEXT PRIMARY KEY, date_added TEXT, vendor TEXT,
                         product TEXT, name TEXT, description TEXT);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        """
    )


def _best_cvss(metrics: dict):
    """Return (score, version) preferring v4, then v3.1/v3.0, then v2."""
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData") or {}
        if "baseScore" in data:
            return float(data["baseScore"]), ver
    return None, None


def _load_cve(db: sqlite3.Connection) -> None:
    path = FEEDS / "nvdcve-2.0-2026.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    cves, cwes, matches = [], [], []
    for entry in data.get("vulnerabilities", []):
        cve = entry["cve"]
        cid = cve["id"]
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        score, cvss_ver = _best_cvss(cve.get("metrics") or {})
        cves.append((cid, desc, score, cvss_ver))

        seen = set()
        for weak in cve.get("weaknesses", []):
            for d in weak.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val not in seen:
                    seen.add(val)
                    cwes.append((cid, val))

        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    parts = m.get("criteria", "").split(":")
                    if len(parts) < 6:
                        continue
                    vendor, product, version = parts[3], parts[4], parts[5]
                    exact = version if version not in ("*", "-") else None
                    matches.append((
                        cid, vendor, product, exact,
                        m.get("versionStartIncluding") or m.get("versionStartExcluding"),
                        1 if m.get("versionStartIncluding") else 0,
                        m.get("versionEndIncluding") or m.get("versionEndExcluding"),
                        1 if m.get("versionEndIncluding") else 0,
                    ))
    db.executemany("INSERT OR IGNORE INTO cve VALUES (?,?,?,?,0)", cves)
    db.executemany("INSERT INTO cve_cwe VALUES (?,?)", cwes)
    db.executemany("INSERT INTO cve_match VALUES (?,?,?,?,?,?,?,?)", matches)
    db.commit()


def _load_kev(db: sqlite3.Connection) -> None:
    path = FEEDS / "known_exploited_vulnerabilities.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = [(v["cveID"], v.get("dateAdded"), v.get("vendorProject"),
             v.get("product"), v.get("vulnerabilityName"),
             v.get("shortDescription")) for v in data.get("vulnerabilities", [])]
    db.executemany("INSERT OR IGNORE INTO kev VALUES (?,?,?,?,?,?)", rows)
    db.execute("UPDATE cve SET in_kev = 1 WHERE id IN (SELECT cve_id FROM kev)")
    db.commit()


def _load_cpe(db: sqlite3.Connection) -> None:
    """Stream the CPE dictionary tarball chunk by chunk (900 MB uncompressed)."""
    cve_products = {(v, p) for v, p in
                    db.execute("SELECT DISTINCT vendor, product FROM cve_match")}
    path = FEEDS / "nvdcpe-2.0.tar.gz"
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            if not member.name.endswith(".json"):
                continue
            chunk = json.load(tar.extractfile(member))
            products, versions = [], []
            for item in chunk.get("products", []):
                cpe = item.get("cpe", {})
                parts = cpe.get("cpeName", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                title = next((t["title"] for t in cpe.get("titles", [])
                              if t.get("lang") == "en"), product)
                products.append((vendor, product, title))
                if (vendor, product) in cve_products and version not in ("*", "-"):
                    versions.append((vendor, product, version))
            db.executemany("INSERT OR IGNORE INTO cpe_product VALUES (?,?,?)", products)
            db.executemany("INSERT INTO cpe_version VALUES (?,?,?)", versions)
            db.commit()


def _load_cwe(db: sqlite3.Connection) -> None:
    path = FEEDS / "cwec_latest.xml.zip"
    with zipfile.ZipFile(path) as zf:
        raw = zf.read(zf.namelist()[0])
    rows, links = [], []
    for _, elem in ET.iterparse(io.BytesIO(raw), events=("end",)):
        if _localname(elem.tag) != "Weakness":
            continue
        cid = "CWE-" + elem.get("ID", "")
        name = elem.get("Name", "")
        desc = ""
        for child in elem:
            if _localname(child.tag) == "Description":
                desc = "".join(child.itertext()).strip()
            if _localname(child.tag) == "Related_Attack_Patterns":
                for rap in child:
                    cap = rap.get("CAPEC_ID")
                    if cap:
                        links.append((cid, "CAPEC-" + cap))
        rows.append((cid, name, desc))
        elem.clear()
    db.executemany("INSERT OR IGNORE INTO cwe VALUES (?,?,?)", rows)
    db.executemany("INSERT INTO cwe_capec VALUES (?,?)", links)
    db.commit()


def _load_capec(db: sqlite3.Connection) -> None:
    path = FEEDS / "capec_latest.xml"
    rows, links = [], []
    for _, elem in ET.iterparse(str(path), events=("end",)):
        if _localname(elem.tag) != "Attack_Pattern":
            continue
        cid = "CAPEC-" + elem.get("ID", "")
        name = elem.get("Name", "")
        desc = ""
        for child in elem:
            if _localname(child.tag) == "Description":
                desc = "".join(child.itertext()).strip()
            if _localname(child.tag) == "Related_Weaknesses":
                for rw in child:
                    cwe = rw.get("CWE_ID")
                    if cwe:
                        links.append((cid, "CWE-" + cwe))
        rows.append((cid, name, desc))
        elem.clear()
    db.executemany("INSERT OR IGNORE INTO capec VALUES (?,?,?)", rows)
    db.executemany("INSERT INTO capec_cwe VALUES (?,?)", links)
    db.commit()


def _load_meta(db: sqlite3.Connection) -> None:
    snap = FEEDS / "SNAPSHOT.json"
    info = json.loads(snap.read_text()) if snap.exists() else {}
    db.execute("INSERT OR REPLACE INTO meta VALUES ('snapshot', ?)",
               (info.get("snapshot", "unknown"),))
    db.execute("INSERT OR REPLACE INTO meta VALUES ('feeds', ?)",
               (json.dumps(sorted(info.get("sources", {}).keys())),))
    db.commit()


def load() -> sqlite3.Connection:
    """Parse every feed and return an in-memory connection, ready to query."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("PRAGMA temp_store = MEMORY")
    db.row_factory = sqlite3.Row
    _schema(db)
    _load_cve(db)
    _load_kev(db)
    _load_cpe(db)
    _load_cwe(db)
    _load_capec(db)
    _load_meta(db)
    db.executescript(
        """
        CREATE INDEX i_match ON cve_match(vendor, product);
        CREATE INDEX i_cwe ON cve_cwe(cve_id);
        CREATE INDEX i_prod ON cpe_product(product);
        CREATE INDEX i_ver ON cpe_version(vendor, product);
        CREATE INDEX i_cwecap ON cwe_capec(cwe_id);
        CREATE INDEX i_capcwe ON capec_cwe(capec_id);
        """
    )
    db.commit()
    return db
