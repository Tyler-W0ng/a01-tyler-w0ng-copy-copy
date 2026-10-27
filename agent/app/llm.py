"""The three places the agent asks the model, all about naming only.

  extract_products(text)  - read a messy document and list software+versions
  suggest_name(raw)       - clean a product name search could not resolve
  same_product(...)       - of several CPE identities, which are one product

The model never produces CVEs or CWEs; those come from the MCP server. In
same_product it only chooses among CPE identities the server already returned,
so it can keep or drop a real identity but never invent one. Every call is
best-effort: a refusal, a budget error or an unparseable reply raises, and the
caller falls back to what deterministic code already found. We parse the first
JSON value in the reply, because Claude may wrap it in prose or a code fence
(handout section 3).
"""

import json
import logging

from langchain_openai import ChatOpenAI

from app import config

log = logging.getLogger(__name__)

_EXTRACT_PROMPT = (
    "You are a security analyst reading one reconnaissance artifact (a scan, "
    "an SBOM, banners, a package list, or notes). List EVERY software product "
    "that appears WITH A CONCRETE VERSION - applications, servers, libraries "
    "and services alike. Include low-level components such as shared libraries "
    "as long as they have a version; do NOT try to decide whether something is "
    "\"part of the operating system\". Skip only entries that have no version "
    "at all: a process or service listing (ps, top), a routing table, or "
    "resource columns (PID, CPU%, memory, RSS, time) carry NO software "
    "version - never read a bare numeric column as one, and return an empty "
    "array for such a document unless a real version string is explicitly "
    "shown. A product and its version may sit on different lines, or the "
    "version may be buried in protocol/binary noise (a service handshake); "
    "pair each product with the version that is really its own, and copy the "
    "version exactly as it appears. Use the product's name as written in the "
    "document. Reply with ONLY a JSON array of objects: [{\"name\": \"...\", "
    "\"version\": \"...\", \"evidence\": \"the exact line you saw it on\"}]. "
    "Empty array if none."
)

_SUGGEST_PROMPT = (
    "Give the canonical upstream product name for this software, as it would "
    "appear in the NVD CPE dictionary (lowercase, one or two words, no version, "
    "no distro prefix). Reply with ONLY the name."
)

_SAME_PRODUCT_PROMPT = (
    "You match a detected software product to entries in the NVD CPE "
    "dictionary. You are given one detected product and a list of candidate "
    "CPE products, each as \"vendor:product - title\". Reply with ONLY a JSON "
    "array of the \"vendor:product\" strings that are the SAME core product as "
    "the detected one - the identical software that NVD merely files under a "
    "different edition or vendor name (for example a bare name and its "
    "'...server' or 'open_source' form). EXCLUDE separate products in the same "
    "family or brand: clustering/HA editions, connectors, client libraries, "
    "drivers, GUIs and workbenches, proxies, routers, controllers, agents and "
    "plugins are their own products, even when the name and version look "
    "similar. When unsure, leave it out. Choose only from the candidates "
    "given; use an empty array if none match."
)


def _model() -> ChatOpenAI:
    return ChatOpenAI(model=config.MODEL, base_url=config.BASE_URL,
                      api_key=config.API_KEY, temperature=0, timeout=60,
                      max_retries=1)


def _first_json(text: str):
    """The first JSON array/object in a string, or None."""
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "[{":
            try:
                value, _ = dec.raw_decode(text[i:])
                return value
            except json.JSONDecodeError:
                continue
    return None


async def extract_products(text: str, run_config) -> list:
    reply = await _model().ainvoke(
        [{"role": "system", "content": _EXTRACT_PROMPT},
         {"role": "user", "content": text[:12000]}], run_config)
    value = _first_json(reply.content)
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, dict) and item.get("name") and item.get("version"):
            out.append({"name": str(item["name"]).strip(),
                        "version": str(item["version"]).strip(),
                        "evidence": str(item.get("evidence", ""))[:200]})
    return out


async def suggest_name(raw: str, run_config) -> str:
    reply = await _model().ainvoke(
        [{"role": "system", "content": _SUGGEST_PROMPT},
         {"role": "user", "content": raw}], run_config)
    return reply.content.strip().split("\n")[0].strip().lower()[:60]


async def same_product(name: str, version, candidates: list, run_config) -> set:
    """Which of `candidates` (CPE rows) are the same software as `name`?

    Returns a set of (vendor, product) tuples, a subset of the input. The
    model only filters identities the server already returned; anything it
    names that was not offered is dropped, so it cannot inject a product.
    """
    if not candidates:
        return set()
    lines = "\n".join(f'- {c["vendor"]}:{c["product"]} - {c.get("title", "")}'
                      for c in candidates)
    user = f'Detected product: {name} {version or ""}\nCandidates:\n{lines}'
    reply = await _model().ainvoke(
        [{"role": "system", "content": _SAME_PRODUCT_PROMPT},
         {"role": "user", "content": user}], run_config)
    value = _first_json(reply.content)
    if not isinstance(value, list):
        return set()
    allowed = {(c["vendor"].lower(), c["product"].lower()) for c in candidates}
    out = set()
    for s in value:
        if not isinstance(s, str) or ":" not in s:
            continue
        v, _, p = s.strip().lower().partition(":")
        if (v, p) in allowed:
            out.add((v, p))
    return out
