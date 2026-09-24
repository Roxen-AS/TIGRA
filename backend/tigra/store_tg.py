"""TigerGraph-backed graph store: same interface and JSON shapes as store_local.LocalGraphStore.

Two transports for the installed queries in tigergraph/queries.gsql:
  * REST via pyTigerGraph (GRAPH_BACKEND=tigergraph)
  * the official TigerGraph MCP server (GRAPH_BACKEND=mcp): the agent calls `tigergraph__run_installed_query`
    and `tigergraph__add_node` / `tigergraph__add_edge` over MCP stdio, exactly like an LLM tool call.
"""
from __future__ import annotations

import asyncio
import csv
import json
import os
import re
import statistics
import sys
import threading
from datetime import datetime, timedelta

from . import config


def _q(vals: list[float], q: float) -> float | None:
    """Linear-interpolated quantile, identical to DuckDB quantile_cont used by the local store."""
    if not vals:
        return None
    s = sorted(vals)
    pos = q * (len(s) - 1)
    lo = int(pos)
    return s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (pos - lo)


def _none(v):
    return None if v in ("", None) else v


def _num(v):
    try:
        return None if v in ("", None) else float(v)
    except ValueError:
        return None


def _txn(v: dict) -> dict:
    """Flatten a Txn vertex into the local store's row shape (TigerGraph has no NULLs; '' means missing)."""
    a = v.get("attributes", v)
    out = {k: _none(a.get(k)) for k in ("ts", "product", "channel", "card_id", "customer_id", "p_email", "r_email",
                                          "device_id", "device_status", "proxy", "device_type", "M1", "M2", "M3", "M4", "M5", "M6")}
    out.update(txn_id=int(a.get("txn_id") or v.get("v_id")), amt=float(a["amt"]), risk_score=float(a.get("risk_score", 0)),
               addr1=_num(a.get("addr1")), addr2=_num(a.get("addr2")), dist1=_num(a.get("dist1")),
               C1=_num(a.get("C1")), C13=_num(a.get("C13")), D1=_num(a.get("D1")), D15=_num(a.get("D15")))
    return out


class _MCPBridge:
    """Keeps one tigergraph-mcp stdio session open on a background event loop and exposes a sync call()."""

    def __init__(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        cmd = os.getenv("TG_MCP_COMMAND", "tigergraph-mcp")
        self._params = StdioServerParameters(command=cmd, args=[], env={**os.environ})
        self._client, self._session_cls = stdio_client, ClientSession
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(60)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())

    async def _main(self):
        async with self._client(self._params) as (r, w):
            async with self._session_cls(r, w) as s:
                await s.initialize()
                self.session = s
                self._ready.set()
                await asyncio.Event().wait()  # hold the session open for the process lifetime

    def call(self, tool: str, args: dict) -> dict:
        fut = asyncio.run_coroutine_threadsafe(self.session.call_tool(tool, args), self._loop)
        res = fut.result(120)
        text = "".join(getattr(c, "text", "") for c in res.content)
        m = re.search(r"```json\n(.*?)\n```", text, re.S)
        body = json.loads(m.group(1) if m else text)
        if not body.get("success", True):
            raise RuntimeError(body.get("error") or text[:300])
        return body.get("data") or {}


class TigerGraphStore:
    def __init__(self, via_mcp: bool = False):
        self.via_mcp = via_mcp
        self.backend = "tigergraph-mcp" if via_mcp else "tigergraph"
        if via_mcp:
            self._mcp = _MCPBridge()
        else:
            from pyTigerGraph import TigerGraphConnection
            self.conn = TigerGraphConnection(host=config.TG_HOST, graphname=config.TG_GRAPH, username=config.TG_USERNAME,
                                             password=config.TG_PASSWORD, gsqlSecret=config.TG_SECRET,
                                             tgCloud="tgcloud" in config.TG_HOST)
            if config.TG_SECRET:
                self.conn.getToken(config.TG_SECRET)
        with open(config.DATA_DIR / "case_pack.csv", newline="", encoding="utf-8") as f:
            self._alerts = {r["case_id"]: r for r in csv.DictReader(f)}

    # ------------------------------------------------------------------ transport
    def _run(self, query: str, **params) -> list[dict]:
        params = {k: v for k, v in params.items() if v is not None}
        if self.via_mcp:
            return self._mcp.call("tigergraph__run_installed_query",
                                  {"graph_name": config.TG_GRAPH, "query_name": query, "params": params})["result"]
        return self.conn.runInstalledQuery(query, params, timeout=60000)

    @staticmethod
    def _pick(res: list[dict], key: str):
        for block in res:
            if key in block:
                return block[key]
        return None

    def _upsert_vertex(self, vtype: str, vid: str, attrs: dict):
        if self.via_mcp:
            self._mcp.call("tigergraph__add_node", {"graph_name": config.TG_GRAPH, "vertex_type": vtype, "vertex_id": vid, "attributes": attrs})
        else:
            self.conn.upsertVertex(vtype, vid, attrs)

    def _upsert_edge(self, st: str, sid: str, et: str, tt: str, tid: str):
        if self.via_mcp:
            self._mcp.call("tigergraph__add_edge", {"graph_name": config.TG_GRAPH, "source_vertex_type": st, "source_vertex_id": sid,
                                                    "edge_type": et, "target_vertex_type": tt, "target_vertex_id": tid})
        else:
            self.conn.upsertEdge(st, sid, et, tt, tid)

    # ------------------------------------------------------------------ same API as LocalGraphStore
    def list_alerts(self) -> list[dict]:
        return sorted(self._alerts.values(), key=lambda r: r["case_id"])

    def get_alert(self, case_id: str) -> dict | None:
        return self._alerts.get(case_id)

    def get_transaction(self, txn_id: int) -> dict | None:
        if self.via_mcp:
            data = self._mcp.call("tigergraph__get_node", {"graph_name": config.TG_GRAPH, "vertex_type": "Txn", "vertex_id": str(txn_id)})
            v = data.get("vertex") or data.get("result") or data
            v = v[0] if isinstance(v, list) else v
        else:
            got = self.conn.getVerticesById("Txn", str(txn_id))
            v = got[0] if got else None
        if not v:
            return None
        t = _txn(v)
        t.update(device_profile=None, os=None, browser=None, device_info=None)
        if t["device_id"]:
            if self.via_mcp:
                d = self._mcp.call("tigergraph__get_node", {"graph_name": config.TG_GRAPH, "vertex_type": "DeviceProfile", "vertex_id": t["device_id"]})
                d = d.get("vertex") or d
                d = d[0] if isinstance(d, list) else d
            else:
                d = self.conn.getVerticesById("DeviceProfile", t["device_id"])[0]
            a = d.get("attributes", d)
            t.update(device_profile=a.get("profile"), os=_none(a.get("os")), browser=_none(a.get("browser")), device_info=_none(a.get("device_info")))
        return t

    def customer_cards(self, customer_id: str) -> list[dict]:
        cards = self._pick(self._run("customer_cards", cust=customer_id), "cards") or []
        return [{"card_id": c["v_id"], "network": c["attributes"]["network"], "card_type": c["attributes"]["card_type"],
                 "n_txn": c["attributes"]["@n"]} for c in cards]

    def card_profile(self, card_id: str, before_ts: str) -> dict:
        rows = [r["attributes"] for r in self._pick(self._run("card_history", card=card_id, before_ts=before_ts), "txns") or []]
        amts = [float(r["amt"]) for r in rows]
        out = {"n": len(rows), "first_ts": min((r["ts"] for r in rows), default=None), "last_ts": max((r["ts"] for r in rows), default=None),
               "amt_median": statistics.median(amts) if amts else None, "amt_p25": _q(amts, 0.25), "amt_p75": _q(amts, 0.75),
               "amt_p95": _q(amts, 0.95), "amt_max": max(amts, default=None),
               "online_share": (sum(r["channel"] == "online" for r in rows) / len(rows)) if rows else None,
               "n_devices": len({r["device_id"] for r in rows if r["device_id"]}), "n_regions": len({r["addr1"] for r in rows if r["addr1"]})}
        prod: dict[str, list[float]] = {}
        reg: dict[str, list[str]] = {}
        em: dict[str, int] = {}
        for r in rows:
            prod.setdefault(r["product"], []).append(float(r["amt"]))
            if r["addr1"]:
                reg.setdefault(r["addr1"], []).append(r["ts"])
            if r["p_email"]:
                em[r["p_email"]] = em.get(r["p_email"], 0) + 1
        out["products"] = sorted(({"product": p, "n": len(v), "amt_median": statistics.median(v), "amt_max": max(v)} for p, v in prod.items()), key=lambda d: -d["n"])
        out["regions"] = sorted(({"region": float(k), "n": len(v), "first_ts": min(v), "last_ts": max(v), "days": len({x[:10] for x in v})}
                                 for k, v in reg.items()), key=lambda d: -d["n"])[:12]
        out["emails"] = [{"email": k, "n": v} for k, v in sorted(em.items(), key=lambda kv: -kv[1])[:8]]
        return out

    def card_window(self, card_id: str, start_ts: str, end_ts: str, limit: int = 400) -> list[dict]:
        return [_txn(v) for v in self._pick(self._run("card_window", card=card_id, start_ts=start_ts, end_ts=end_ts, lim=limit), "txns") or []]

    def _seen(self, card_id: str, attr: str, val: str, before_ts: str) -> dict:
        res = self._run("card_attr_seen", card=card_id, attr=attr, val=val, before_ts=before_ts)
        n = self._pick(res, "n") or 0
        first = self._pick(res, "first_ts")
        return {"n": n, "first_ts": first if n else None, "days": self._pick(res, "days") or 0}

    def region_history(self, card_id: str, region: float, before_ts: str) -> dict:
        return self._seen(card_id, "region", f"{region:g}" if isinstance(region, float) else str(region), before_ts)

    def device_seen_on_card(self, card_id: str, device_id: str, before_ts: str) -> dict:
        d = self._seen(card_id, "device", device_id, before_ts)
        return {"n": d["n"], "first_ts": d["first_ts"]}

    def email_seen_on_card(self, card_id: str, email: str, before_ts: str) -> dict:
        d = self._seen(card_id, "email", email, before_ts)
        return {"n": d["n"], "first_ts": d["first_ts"]}

    def amount_recurrence(self, card_id: str, txn_id: int, amt: float, product: str, region: float | None, tol: float = 0.02) -> dict:
        band = max(tol * amt, 0.5)
        res = self._run("amount_recurrence", card=card_id, before_txn=int(txn_id), lo=amt - band, hi=amt + band, prod=product,
                        reg=f"{region:g}" if region is not None else "")
        hits = [{"txn_id": int(h["attributes"]["txn_id"]), "ts": h["attributes"]["ts"], "amt": float(h["attributes"]["amt"]),
                 "addr1": _num(h["attributes"]["addr1"]), "p_email": _none(h["attributes"]["p_email"]),
                 "device_id": _none(h["attributes"]["device_id"])} for h in self._pick(res, "hits") or []]
        return {"hits": hits, "scope_n": self._pick(res, "scope_n") or 0}

    def device_neighbors(self, device_id: str, center_ts: str, days: int = 14) -> dict:
        c = datetime.fromisoformat(center_ts)
        res = self._run("device_neighbors", dev=device_id, start_ts=str(c - timedelta(days=days)), end_ts=str(c + timedelta(days=days)))
        dev = (self._pick(res, "device") or [{}])[0].get("attributes", {})
        cases = [{"case_id": x["v_id"], "card_id": x["attributes"]["card_id"], "outcome": x["attributes"]["outcome"],
                  "pattern": x["attributes"]["pattern"], "opened_at": x["attributes"]["opened_at"]} for x in self._pick(res, "closed_cases") or []]
        return {"device": {"profile": dev.get("profile"), "n_txn": self._pick(res, "n_txn") or 0, "n_cards": self._pick(res, "n_cards") or 0,
                           "first_ts": self._pick(res, "first_ts"), "last_ts": self._pick(res, "last_ts")},
                "window_days": days, "window_txns": [_txn(v) for v in self._pick(res, "window_txns") or []],
                "closed_cases": sorted(cases, key=lambda x: x["opened_at"])}

    def prior_cases(self, customer_id: str, before_ts: str) -> list[dict]:
        res = self._run("prior_cases", cust=customer_id, before_ts=before_ts)
        out = []
        for c in self._pick(res, "closed_cases") or []:
            a = c["attributes"]
            out.append({"case_id": c["v_id"], "card_id": a["card_id"], "outcome": a["outcome"], "pattern": a["pattern"],
                        "opened_at": a["opened_at"], "closed_at": a["closed_at"], "exposure_usd": a["exposure_usd"], "n_txns": a["n_txns"],
                        "report_filed": a["report_filed"], "analyst_notes": a["analyst_notes"], "source": "closed_case"})
        for c in self._pick(res, "agent_cases") or []:
            a = c["attributes"]
            out.append({"case_id": c["v_id"], "card_id": a["card_id"], "outcome": a["verdict"], "pattern": a["pattern"],
                        "opened_at": a["opened_at"], "closed_at": None, "exposure_usd": a["exposure_usd"], "n_txns": None,
                        "report_filed": a["sar_filed"], "analyst_notes": a["summary"], "source": "agent_case"})
        return sorted(out, key=lambda r: r["opened_at"])

    def closed_case_features(self) -> list[dict]:
        rows = []
        for c in self._pick(self._run("closed_case_features"), "cases") or []:
            a = c["attributes"]
            n = max(a["@n"], 1)
            rows.append({"case_id": c["v_id"], "card_id": a["card_id"], "customer_id": a["customer_id"], "outcome": a["outcome"],
                         "pattern": a["pattern"], "opened_at": a["opened_at"], "exposure_usd": a["exposure_usd"], "n_txns": a["n_txns"],
                         "connected_card_ids": None, "analyst_notes": a["analyst_notes"], "report_filed": a["report_filed"],
                         "online_share": a["@online"] / n, "new_device_share": a["@newdev"] / n, "proxy_share": a["@proxy"] / n,
                         "amt_min": a["@amin"], "amt_max": a["@amax"],
                         "span_min": (datetime.fromisoformat(a["@t1"]) - datetime.fromisoformat(a["@t0"])).total_seconds() / 60,
                         "product": max(a["@prod"], key=a["@prod"].get) if a["@prod"] else None, "risk_max": a["@rmax"],
                         "device_ids": list(a["@devs"])})
        return rows

    def agent_cases(self) -> list[dict]:
        return []

    def write_case(self, rec: dict) -> str:
        cid = rec["graph_case_id"]
        self._upsert_vertex("FraudCase", cid, {
            "case_id": rec["case_id"], "card_id": rec["card_id"], "customer_id": rec["customer_id"], "opened_at": rec["opened_at"],
            "updated_at": rec["updated_at"].replace("T", " "), "status": rec["status"], "verdict": rec["verdict"], "pattern": rec["pattern"],
            "fraud_probability": rec["fraud_probability"], "exposure_usd": rec["exposure_usd"], "summary": rec["summary"],
            "sar_filed": bool(rec["sar_filed"]), "actions": "|".join(rec["actions"])})
        self._upsert_edge("FraudCase", cid, "CASE_ON_CARD", "Card", rec["card_id"])
        for t in rec["txn_ids"]:
            self._upsert_edge("FraudCase", cid, "CASE_INVOLVES", "Txn", str(t))
        for k in rec["connected_card_ids"]:
            self._upsert_edge("FraudCase", cid, "CASE_CONNECTED", "Card", k)
        for d in rec["device_ids"]:
            self._upsert_edge("FraudCase", cid, "CASE_DEVICE", "DeviceProfile", d)
        return cid

    def reset_agent_cases(self) -> None:
        if not self.via_mcp:
            self.conn.delVertices("FraudCase")

    def stats(self) -> dict:
        if self.via_mcp:
            return {"backend": self.backend}
        c = self.conn.getVertexCount("*")
        return {"transactions": c.get("Txn"), "cards": c.get("Card"), "customers": c.get("Customer"), "devices": c.get("DeviceProfile"),
                "closed_cases": c.get("ClosedCase"), "agent_cases": c.get("FraudCase")}
