"""Case memory: retrieve similar past cases (closed history + cases this agent wrote to the graph).

Similarity = cosine over a behavioural feature vector (channel, device novelty, proxy, amount scale, burst span,
product) + graph proximity (same card / same customer / shared device). Graph proximity matters because the
dataset's recurring fraud concentrates on the same cards and devices.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass

import numpy as np

PRODUCTS = ("W", "C", "H", "R", "S")


def _f(x) -> float:
    """Missing aggregates (SQL NULL -> None/NaN, e.g. no identity record on any transaction) count as 0."""
    try:
        x = float(x)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if math.isnan(x) else x


def feature_vector(online_share: float, new_device_share: float, proxy_share: float, amt_min: float, amt_max: float,
                   n_txns: int, span_min: float, product: str | None) -> np.ndarray:
    online_share, new_device_share, proxy_share = _f(online_share), _f(new_device_share), _f(proxy_share)
    amt_min = None if amt_min is None else _f(amt_min)
    amt_max, n_txns, span_min = _f(amt_max), int(_f(n_txns)), _f(span_min)
    v = [
        online_share, new_device_share, proxy_share,
        math.log1p(max(amt_min or 0, 0)) / 8, math.log1p(max(amt_max or 0, 0)) / 8,
        math.log1p(max(n_txns or 1, 1)) / 4, math.log1p(max(span_min or 0, 0)) / 10,
        1.0 if (amt_min or 99) < 5 else 0.0,
        1.0 if 400 <= (amt_max or 0) < 500 and (n_txns or 0) >= 3 else 0.0,
    ] + [1.0 if product == p else 0.0 for p in PRODUCTS]
    a = np.asarray(v, dtype=np.float32)
    n = np.linalg.norm(a)
    return a / n if n else a


@dataclass
class MemoryItem:
    case_id: str
    card_id: str
    customer_id: str
    outcome: str      # confirmed_fraud | cleared | fraud | legitimate | uncertain
    pattern: str
    opened_at: str
    exposure_usd: float
    devices: frozenset
    notes: str
    source: str       # closed_case | agent_case

    @property
    def is_fraud(self) -> bool | None:
        return {"confirmed_fraud": True, "fraud": True, "cleared": False, "legitimate": False}.get(self.outcome)


class CaseMemory:
    def __init__(self, store):
        self.store = store
        self.items: list[MemoryItem] = []
        vecs = []
        for r in store.closed_case_features():
            self.items.append(MemoryItem(r["case_id"], r["card_id"], r["customer_id"], r["outcome"], r["pattern"],
                                         r["opened_at"], r["exposure_usd"] or 0.0, frozenset(r["device_ids"] or []),
                                         r["analyst_notes"], "closed_case"))
            vecs.append(feature_vector(r["online_share"], r["new_device_share"], r["proxy_share"], r["amt_min"],
                                       r["amt_max"], r["n_txns"], r["span_min"], r["product"]))
        self.matrix = np.stack(vecs)
        self.n_closed = len(self.items)
        for rec in store.agent_cases():  # cases this agent wrote earlier (persisted in the graph) rejoin the index
            if rec.get("vec"):
                self.add(rec, np.asarray(json.loads(rec["vec"]), dtype=np.float32))

    def add(self, rec: dict, vec: np.ndarray) -> None:
        """Called after the agent writes a case: the next investigation can retrieve it immediately."""
        keep = [k for k, it in enumerate(self.items) if it.case_id != rec["graph_case_id"]]
        if len(keep) < len(self.items):  # re-investigation replaces the earlier version of the same case
            self.items = [self.items[k] for k in keep]
            self.matrix = self.matrix[keep]
        devices = rec.get("device_ids") or []
        if isinstance(devices, str):
            devices = json.loads(devices)
        self.items.append(MemoryItem(rec["graph_case_id"], rec["card_id"], rec["customer_id"], rec["verdict"],
                                     rec["pattern"], rec["opened_at"], rec.get("exposure_usd") or 0.0,
                                     frozenset(devices), rec.get("summary", ""), "agent_case"))
        self.matrix = np.vstack([self.matrix, vec[None, :]])

    def similar(self, vec: np.ndarray, card_id: str, customer_id: str, devices: set[str], before_ts: str,
                k: int = 5, fraud_only: bool = False) -> list[dict]:
        """fraud_only: for customer disputes, compare against confirmed cases (cleared history = model alerts only)."""
        sims = np.nan_to_num(self.matrix @ vec)  # a NaN would silently break the ranking below
        scored = []
        for i, item in enumerate(self.items):
            if item.opened_at >= before_ts:      # memory only contains what was known when the alert fired
                continue
            if fraud_only and item.is_fraud is False:
                continue
            s = float(sims[i])
            link = []
            if item.card_id == card_id:
                s += 0.35; link.append("same card")
            elif item.customer_id == customer_id:
                s += 0.2; link.append("same customer")
            shared = devices & item.devices
            if shared:
                s += 0.6; link.append("shared device " + ",".join(sorted(shared)))
            scored.append((s, i, link))
        scored.sort(key=lambda t: -t[0])
        out = []
        for s, i, link in scored[:k]:
            it = self.items[i]
            out.append({"case_id": it.case_id, "score": round(s, 3), "outcome": it.outcome, "pattern": it.pattern,
                        "card_id": it.card_id, "opened_at": it.opened_at, "exposure_usd": it.exposure_usd,
                        "link": link, "notes": it.notes[:260], "source": it.source})
        return out
