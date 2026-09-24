"""Validate cases/*.json against the README answer format and the fraud policy.

  python -m tigra.validate          -> prints problems per case, exit code 1 if any

Checks: required fields and types, enums, every ID exists in the dataset, exposure = sum of affected amounts,
legitimate-verdict invariants, sar.file <=> FILE_REPORT in final actions, SAR field completeness, action names and
routes match policy section 2, R10 (no BLOCK_ALL_CARDS without two fraud cards), final == initial when nothing
was requested.
"""
from __future__ import annotations

import json
import re
import sys

import duckdb

from .config import CASES_DIR, DB_PATH
from .policy import ACTIONS, route

STATUS = {"open", "closed_fraud", "closed_legitimate", "escalated"}
VERDICT = {"fraud", "legitimate", "uncertain"}
PATTERN = {"card_testing", "card_not_present_fraud", "card_not_present_new_device", "out_of_region_use",
           "account_takeover", "undocumented", "none"}
REQ = {"customer_validation", "step_up_auth", "analyst_info"}
SOURCES = {"graph", "document", "customer", "external"}


def check(ans: dict, con) -> list[str]:
    errs: list[str] = []
    e = errs.append
    for k, t in {"case_id": str, "case": dict, "evidence_requests": list, "next_best_actions": dict, "sar": dict,
                 "stop_reason": str, "tool_calls": int, "tokens": int, "latency_s": (int, float)}.items():
        if not isinstance(ans.get(k), t):
            e(f"top-level {k} missing or wrong type")
    c = ans.get("case", {})
    if c.get("status") not in STATUS: e(f"case.status {c.get('status')}")
    if c.get("verdict") not in VERDICT: e(f"case.verdict {c.get('verdict')}")
    if c.get("pattern") not in PATTERN: e(f"case.pattern {c.get('pattern')}")
    p = c.get("fraud_probability")
    if not isinstance(p, (int, float)) or not 0 <= p <= 1: e("fraud_probability not in [0,1]")
    if c.get("pattern") == "undocumented" and len(c.get("pattern_description", "")) < 40: e("undocumented pattern needs a description")
    if c.get("pattern") != "undocumented" and c.get("pattern_description"): e("pattern_description must be empty unless undocumented")

    txns = c.get("affected_txn_ids", [])
    if txns:
        rows = con.execute(f"SELECT txn_id, amt FROM txn WHERE txn_id IN ({','.join('?' * len(txns))})", [int(t) for t in txns]).fetchall()
        if len(rows) != len(set(txns)): e("affected_txn_ids contains unknown ids")
        if abs(sum(abs(a) for _, a in rows) - c.get("exposure_usd", -1)) > 0.02: e("exposure_usd != sum of affected amounts")
    if c.get("first_suspicious_txn_id") and c["first_suspicious_txn_id"] not in txns: e("first_suspicious_txn_id not in affected")
    cards = c.get("connected_card_ids", [])
    if cards:
        n = con.execute(f"SELECT count(*) FROM card WHERE card_id IN ({','.join('?' * len(cards))})", cards).fetchone()[0]
        if n != len(set(cards)): e("connected_card_ids contains unknown cards")
    for prof in c.get("connected_device_profiles", []):
        if not con.execute("SELECT 1 FROM device WHERE profile = ?", [prof]).fetchone(): e(f"unknown device profile {prof}")
    for cc in c.get("similar_prior_cases", []):
        if not con.execute("SELECT 1 FROM closed_case WHERE case_id = ?", [cc]).fetchone(): e(f"unknown closed case {cc}")
    for ev in c.get("evidence", []):
        if set(ev) != {"claim", "source", "ref", "entity_ids"} or ev["source"] not in SOURCES: e(f"bad evidence item {str(ev)[:80]}")
        for i in ev.get("entity_ids", []):
            if re.fullmatch(r"\d{7}", i):
                if not con.execute("SELECT 1 FROM txn WHERE txn_id = ?", [int(i)]).fetchone(): e(f"evidence txn {i} unknown")
            elif re.fullmatch(r"C\d{5}-K\d", i):
                if not con.execute("SELECT 1 FROM card WHERE card_id = ?", [i]).fetchone(): e(f"evidence card {i} unknown")
            elif re.fullmatch(r"C\d{5}", i):
                if not con.execute("SELECT 1 FROM customer WHERE customer_id = ?", [i]).fetchone(): e(f"evidence customer {i} unknown")
            elif re.fullmatch(r"CC-\d{4}", i):
                if not con.execute("SELECT 1 FROM closed_case WHERE case_id = ?", [i]).fetchone(): e(f"evidence case {i} unknown")
            else:
                e(f"evidence entity id {i} is not a dataset id")
    if not isinstance(c.get("written_to_graph"), bool): e("written_to_graph not bool")
    if c.get("written_to_graph") and not c.get("graph_case_id"): e("graph_case_id missing")
    if not 2 <= len(re.findall(r"[.!?](\s|$)", c.get("summary", ""))) + (0 if c.get("summary", "").rstrip().endswith((".", "!", "?")) else 1) <= 8:
        e("summary should be 2-6 sentences")

    if c.get("verdict") == "legitimate" and (txns or c.get("exposure_usd") or ans["sar"].get("file")):
        e("legitimate verdict must have no affected txns, zero exposure and no SAR")

    for r in ans.get("evidence_requests", []):
        if r.get("type") not in REQ or not isinstance(r.get("asked_after_step"), int) or not r.get("assumed_response"): e(f"bad evidence request {r}")

    nba = ans.get("next_best_actions", {})
    for stage in ("initial", "final"):
        lst = nba.get(stage)
        if not lst: e(f"next_best_actions.{stage} empty"); continue
        for a in lst:
            if a.get("action") not in ACTIONS: e(f"{stage}: unknown action {a.get('action')}")
            elif a.get("route") != route(a["action"], c.get("exposure_usd", 0) if stage == "final" else max(c.get("exposure_usd", 0), 0)) \
                    and not (a["action"] == "BLOCK_CARD" and a.get("route") in ("L1", "L2")):
                e(f"{stage}: {a['action']} routed {a.get('route')}")
            if not a.get("reason"): e(f"{stage}: {a.get('action')} has no reason")
    if not ans.get("evidence_requests") and nba.get("final") != nba.get("initial"): e("final must equal initial when no evidence was requested")
    if not nba.get("what_changed"): e("what_changed empty")
    finals = {a["action"] for a in nba.get("final", [])}
    if "BLOCK_ALL_CARDS" in finals: e("R10: BLOCK_ALL_CARDS recommended; verify two fraud cards")

    s = ans.get("sar", {})
    if s.get("file") != ("FILE_REPORT" in finals): e("sar.file disagrees with FILE_REPORT in final actions")
    if s.get("file"):
        if len(re.findall(r"\.\s", s.get("narrative", "") + " ")) < 6: e("SAR narrative should be 6-12 sentences")
        if not s.get("subjects") or not s.get("activity_dates") or len(s["activity_dates"]) != 2: e("SAR subjects/dates incomplete")
        if abs(s.get("total_amount_usd", 0) - c.get("exposure_usd", 0)) > 0.02: e("SAR total != exposure")
    elif s.get("narrative") or s.get("subjects") or s.get("total_amount_usd") or s.get("activity_dates"):
        e("sar.file false but SAR fields not empty")
    if not s.get("reason"): e("sar.reason empty")
    return errs


def main() -> int:
    con = duckdb.connect(str(DB_PATH), read_only=True)
    files = sorted(CASES_DIR.glob("HHG-*.json"))
    bad = 0
    for f in files:
        errs = check(json.loads(f.read_text(encoding="utf-8")), con)
        bad += bool(errs)
        print(f"{f.stem}: {'OK' if not errs else '; '.join(errs)}")
    print(f"{len(files) - bad}/{len(files)} answer files valid")
    return 1 if bad or len(files) != 20 else 0


if __name__ == "__main__":
    sys.exit(main())
