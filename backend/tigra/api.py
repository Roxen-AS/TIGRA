"""HTTP API + static UI.

  uvicorn tigra.api:app --port 8000        (from backend/)

Investigations stream over Server-Sent Events so the UI shows every tool call, piece of evidence, probability
update and recommendation as it happens. L1/L2 actions are recommendations until a human with the right role
approves them; the approval is appended to the case's decision log.
"""
from __future__ import annotations

import json
import queue
import threading
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config
from .policy import APPROVER
from .runtime import runtime, save_case

app = FastAPI(title="TIGRA: TigerGraph Investigative Reasoning Agent", version="1.0")
FRONTEND = config.ROOT / "frontend"
_lock = threading.Lock()  # one investigation mutates case memory at a time
ROLE_RANK = {"TIGRA": 0, "team lead": 1, "fraud manager": 2}


def _case_file(case_id: str) -> Path:
    if not case_id.replace("-", "").isalnum():
        raise HTTPException(400, "bad case id")
    return config.CASES_DIR / f"{case_id}.json"


def _log_file(case_id: str) -> Path:
    return config.CASES_DIR / "decision_log" / f"{case_id}.json"


def _trace_file(case_id: str) -> Path:
    return config.CASES_DIR / "trace" / f"{case_id}.json"


def _read_log(case_id: str) -> list[dict]:
    p = _log_file(case_id)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


@app.on_event("startup")
def _warm() -> None:
    runtime()  # build store, knowledge base and memory index once


@app.get("/api/health")
def health():
    store, kb, memory, agent = runtime()
    return {"backend": store.backend, "llm": agent.llm.enabled, "model": config.LLM_MODEL if agent.llm.enabled else None,
            "kb_docs": len(kb.docs), "memory_items": len(memory.items), "stats": store.stats()}


@app.get("/api/alerts")
def alerts():
    store, *_ = runtime()
    out = []
    for a in store.list_alerts():
        f = _case_file(a["case_id"])
        c = json.loads(f.read_text(encoding="utf-8"))["case"] if f.exists() else None
        out.append({**a, "result": None if c is None else {k: c[k] for k in ("status", "verdict", "pattern", "fraud_probability", "exposure_usd")}})
    return out


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    f = _case_file(case_id)
    if not f.exists():
        raise HTTPException(404, "not investigated yet")
    t = _trace_file(case_id)
    return {"answer": json.loads(f.read_text(encoding="utf-8")), "log": _read_log(case_id),
            "trace": json.loads(t.read_text(encoding="utf-8")) if t.exists() else []}


def _stream(run):
    """Run an investigation in a worker thread and relay its events as SSE."""
    q: queue.Queue = queue.Queue()

    def worker():
        try:
            with _lock:
                run(q.put)
        except Exception as e:  # surfaced to the UI instead of a silent broken stream
            q.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            q.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        while (ev := q.get()) is not None:
            yield f"data: {json.dumps(ev, default=str)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/investigate/{case_id}")
def investigate(case_id: str):
    store, _, _, agent = runtime()
    alert = store.get_alert(case_id)
    if alert is None:
        raise HTTPException(404, "unknown case")

    def run(emit):
        trace: list[dict] = []
        ans = agent.investigate(alert=alert, emit=lambda ev: (trace.append(ev), emit(ev)))
        save_case(ans, trace)
        _append_log(case_id, {"event": "investigated", "by": "TIGRA", "verdict": ans["case"]["verdict"],
                              "executed": [a["action"] for a in ans["next_best_actions"]["final"] if a["route"] == "auto"]})
    return _stream(run)


class AdHoc(BaseModel):
    txn_id: int
    trigger_type: str = Field("analyst_request", pattern="^(risk_score|customer_report|analyst_request)$")
    note: str = ""


@app.get("/api/investigate-txn")
def investigate_txn(txn_id: int, trigger_type: str = "analyst_request", note: str = ""):
    """Investigate any transaction in the dataset (not only the 20 benchmark alerts)."""
    body = AdHoc(txn_id=txn_id, trigger_type=trigger_type, note=note)
    store, _, _, agent = runtime()
    t = store.get_transaction(body.txn_id)
    if t is None:
        raise HTTPException(404, "unknown transaction")
    opened = t["ts"]
    alert = {"case_id": f"ADHOC-{body.txn_id}", "opened_at": opened, "trigger_type": body.trigger_type,
             "trigger_text": body.note or f"Ad-hoc {body.trigger_type.replace('_', ' ')} on transaction {body.txn_id} (${t['amt']:,.2f}, {t['channel']}).",
             "flagged_txn_id": str(body.txn_id), "card_id": t["card_id"], "customer_id": t["customer_id"],
             "risk_score": t["risk_score"] if body.trigger_type == "risk_score" else None}
    return _stream(lambda emit: agent.investigate(alert=alert, emit=emit, write=False))


class Approval(BaseModel):
    action: str
    role: str = Field(..., pattern="^(team lead|fraud manager)$")
    decision: str = Field("approve", pattern="^(approve|reject)$")
    note: str = ""


def _append_log(case_id: str, entry: dict) -> list[dict]:
    log = _read_log(case_id)
    log.append({"at": datetime.utcnow().isoformat(timespec="seconds") + "Z", **entry})
    p = _log_file(case_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(log, indent=2), encoding="utf-8")
    return log


@app.post("/api/cases/{case_id}/approve")
def approve(case_id: str, body: Approval):
    f = _case_file(case_id)
    if not f.exists():
        raise HTTPException(404, "not investigated yet")
    final = json.loads(f.read_text(encoding="utf-8"))["next_best_actions"]["final"]
    item = next((a for a in final if a["action"] == body.action), None)
    if item is None:
        raise HTTPException(400, f"{body.action} is not a recommended action for this case")
    needed = APPROVER[item["route"]]
    if item["route"] == "auto":
        raise HTTPException(400, "auto actions are executed by TIGRA and need no approval")
    if ROLE_RANK[body.role] < ROLE_RANK[needed]:
        raise HTTPException(403, f"{body.action} is routed {item['route']}: requires {needed}")
    return {"log": _append_log(case_id, {"event": body.decision, "action": body.action, "route": item["route"],
                                         "by": body.role, "note": body.note})}


@app.get("/api/graph/{case_id}")
def graph(case_id: str):
    """Ego network for the case view: customer, card, transactions, device profiles, linked cards, prior cases."""
    f = _case_file(case_id)
    if not f.exists():
        raise HTTPException(404, "not investigated yet")
    store, *_ = runtime()
    ans = json.loads(f.read_text(encoding="utf-8"))
    alert = store.get_alert(case_id) or {}
    c = ans["case"]
    nodes, edges = {}, []

    def node(i, kind, label, **kw):
        nodes.setdefault(i, {"id": i, "kind": kind, "label": label, **kw})

    cust, card = alert.get("customer_id"), alert.get("card_id")
    node(cust, "customer", cust)
    node(card, "card", card, focus=True)
    edges.append([cust, card, "OWNS"])
    txns = list(dict.fromkeys(c["affected_txn_ids"] + [str(alert.get("flagged_txn_id"))]))
    for tid in txns[:14]:
        t = store.get_transaction(int(tid))
        if not t:
            continue
        node(tid, "txn", f"${t['amt']:,.0f}", flagged=tid == str(alert.get("flagged_txn_id")), ts=t["ts"], channel=t["channel"])
        edges.append([card, tid, "MADE"])
        if t.get("device_id"):
            node(t["device_id"], "device", (t.get("device_profile") or "")[:34], profile=t.get("device_profile"))
            edges.append([tid, t["device_id"], "FROM_DEVICE"])
    for k in c["connected_card_ids"][:12]:   # keep the picture readable; full list is in the case record
        node(k, "card", k, connected=True)
        dev = next((n["id"] for n in nodes.values() if n["kind"] == "device"), None)
        if dev:
            edges.append([dev, k, "SHARED_DEVICE"])
    for cc in c["similar_prior_cases"][:6]:
        node(cc, "case", cc)
        edges.append([cc, card, "SIMILAR_TO"])
    node(c["graph_case_id"] or f"CASE-{case_id}", "fraudcase", c["graph_case_id"] or case_id)
    edges.append([c["graph_case_id"] or f"CASE-{case_id}", card, "CASE_ON_CARD"])
    return {"nodes": list(nodes.values()), "edges": edges}


@app.get("/api/memory")
def memory_view():
    store, _, memory, _ = runtime()
    return {"agent_cases": store.agent_cases(), "closed_cases": memory.n_closed}


@app.get("/api/policy")
def policy_docs():
    _, kb, *_ = runtime()
    return [{"id": d.doc_id, "title": d.title, "text": d.text} for d in kb.docs if d.source in ("fraud_policy", "fraud_patterns")]


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
