"""The triage pipeline: a LangGraph state machine, one document at a time.

    START -> list_inputs -> read_next --(none left)--> END
                               |   ^
                     (unreadable)  |
                               |   +-------------------------------- write
                               v                                       ^
                            extract -> resolve -> lookup --------------+

Who decides what:

  * the GRAPH decides order and the output ID (the input's own name). Not
    negotiable by a model or by a file's content.
  * CODE does the deterministic work: parse the document (parsers.py), map
    names to CPE identities (resolver.py), and ask the MCP server for the
    CVEs (lookup). The vulnerability facts come only from the server.
  * the MODEL helps with naming only, inside extract (read a messy document)
    and resolve (clean a name search could not place). It never emits a CVE.

The document's bytes stay out of the graph state, in `blobs`, one at a time.
"""

import base64
import hashlib
import json
import logging
import operator
from typing import Annotated, Any, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph

from app import clients, llm, parsers, resolver
from app import config as settings

log = logging.getLogger(__name__)

# Graph steps per item: read_next, extract, resolve, lookup, write.
STEPS_PER_ITEM = 5


class State(TypedDict, total=False):
    queue: list[str]
    item: dict | None
    fmt: str | None
    candidates: list[dict]        # [{name, version, evidence, aliases?}]
    products: list[dict]          # [{cpe, evidence, cves}]
    source: str | None
    error: str | None
    done: Annotated[list[dict], operator.add]


def recursion_limit() -> int:
    return STEPS_PER_ITEM * settings.MAX_ITEMS + 10


def _cpe(aliases: set, version: str) -> str:
    vendor, product = sorted(aliases)[0]
    return f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"


def build(local, remote, only: set[str] | None = None):
    blobs: dict[str, bytes] = {}

    async def list_inputs(state: State) -> dict:
        ids = (await clients.call(local, "list_inputs", {}))["ids"]
        if only:
            ids = [i for i in ids if i in only]
        if len(ids) > settings.MAX_ITEMS:
            log.warning("%d items; processing the first %d", len(ids), settings.MAX_ITEMS)
            ids = ids[:settings.MAX_ITEMS]
        log.info("inputs: %s", ", ".join(ids) or "none")
        return {"queue": ids}

    async def read_next(state: State) -> dict:
        blobs.clear()
        queue = state.get("queue") or []
        if not queue:
            return {"item": None}
        item_id, rest = queue[0], queue[1:]
        fresh = {"queue": rest, "fmt": None, "candidates": [], "products": [],
                 "source": None, "error": None}
        reply = await clients.call(local, "read_input", {"id": item_id})
        if "error" in reply:
            return {**fresh, "source": "error", "error": reply["error"],
                    "item": {"id": item_id}}
        blobs[item_id] = base64.b64decode(reply["data"])
        return {**fresh, "item": {"id": item_id}}

    async def extract(state: State, config: RunnableConfig) -> dict:
        item = state["item"]
        text = blobs[item["id"]].decode("utf-8", "replace")
        fmt, cands, structured = parsers.extract(text)
        # For loose text, also ask the model - it reads what regex cannot.
        if not structured:
            try:
                cands = parsers._dedup(cands + await llm.extract_products(text, config))
            except Exception as exc:                    # noqa: BLE001
                log.warning("%s: llm extract failed: %s", item["id"], exc)
        log.info("%s [%s]: %d candidate(s)", item["id"], fmt, len(cands))
        return {"fmt": fmt, "candidates": cands}

    async def resolve(state: State, config: RunnableConfig) -> dict:
        for c in state["candidates"]:
            if resolver.is_neutral(c["name"]):
                c["aliases"] = set()
                continue
            aliases = resolver.table(c["name"])
            if not aliases:
                hits = (await clients.call(
                    remote, "search_products", {"query": c["name"]}))["candidates"]
                if not hits:
                    try:
                        kw = await llm.suggest_name(c["name"], config)
                        if kw and kw != c["name"].lower():
                            hits = (await clients.call(
                                remote, "search_products", {"query": kw}))["candidates"]
                    except Exception as exc:            # noqa: BLE001
                        log.warning("%s: llm suggest failed: %s", c["name"], exc)
                aliases = resolver.rank_pick(c["name"], hits)
            c["aliases"] = aliases
        return {"candidates": state["candidates"]}

    async def lookup(state: State) -> dict:
        products = []
        for c in state["candidates"]:
            aliases = c.get("aliases") or set()
            if not aliases:
                continue
            version = parsers.normalize_version(c["version"])
            cves: dict[str, list] = {}
            for vendor, product in aliases:
                reply = await clients.call(remote, "vulnerabilities_for",
                                           {"vendor": vendor, "product": product,
                                            "version": version})
                for cve in reply.get("cves", []):
                    cves[cve["id"]] = cve.get("cwes", [])
            products.append({
                "cpe": _cpe(aliases, version),
                "evidence": [c["evidence"]],
                "cves": [{"id": cid, "cwes": cwes} for cid, cwes in cves.items()],
            })
        return {"products": products, "source": "ok"}

    async def write(state: State) -> dict:
        item = state["item"]
        products = state.get("products") or []
        record = {"id": item["id"], "products": products}
        await clients.call(local, "write_output",
                           {"id": item["id"], "content": json.dumps(record, indent=2)})
        n_cve = sum(len(p["cves"]) for p in products)
        summary = f"{len(products)} product(s), {n_cve} CVE(s)"
        log.info("item %-16s %s %s", item["id"], state.get("fmt") or "-",
                 state.get("error") or summary)
        return {"done": [{"id": item["id"], "kind": state.get("fmt"),
                          "source": state.get("source") or "error",
                          "status": "error" if state.get("error") else "ok",
                          "summary": summary, "error": state.get("error")}]}

    def after_read(state: State) -> str:
        if state.get("item") is None:
            return END
        return "write" if state.get("source") == "error" else "extract"

    graph = StateGraph(State)
    graph.add_node("list_inputs", list_inputs)
    graph.add_node("read_next", read_next)
    graph.add_node("extract", extract)
    graph.add_node("resolve", resolve)
    graph.add_node("lookup", lookup)
    graph.add_node("write", write)

    graph.add_edge(START, "list_inputs")
    graph.add_edge("list_inputs", "read_next")
    graph.add_conditional_edges("read_next", after_read, [END, "write", "extract"])
    graph.add_edge("extract", "resolve")
    graph.add_edge("resolve", "lookup")
    graph.add_edge("lookup", "write")
    graph.add_edge("write", "read_next")
    return graph.compile(name="triage")


def summarise(done: list[dict[str, Any]]) -> str:
    return "\n".join(f"{d['id']}: {d['error'] or d['summary']}" for d in done)
