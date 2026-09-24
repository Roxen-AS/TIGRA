"""TIGRA: the TigerGraph Investigative Reasoning Agent.

Flow (mirrors the challenge's core investigation flow):
  1 Trigger       -> load alert + flagged transaction, set a trigger-specific prior
  2 Investigate   -> open a draft case, pull the card baseline and time window from the graph
  3 Gather        -> hypothesis-driven tool plan (device neighbourhood, region, recurrence, memory, documents);
                     every result runs through the detectors and updates the posterior (log-odds fusion)
  4 Assess        -> after each step check the section 6 stopping rule (>=0.85 or <=0.15 with >=2 independent groups)
  5 More evidence -> if unsettled, request customer validation / step-up per R1 and simulate the reply from the
                     posterior (deny / confirm / no reply), recording the assumption
  6 Act           -> initial and final next-best actions from policy.py (routes: auto / L1 / L2)
  7 Explain       -> evidence list, SAR narrative when 3a requires it, summary (LLM with GraphRAG context or template)
  8 Remember      -> write the FraudCase to the graph and to the in-process memory index
"""
from __future__ import annotations

import math
import re
import time
from datetime import datetime, timedelta
from typing import Callable

from . import detectors as D
from .llm import LLM
from .memory import CaseMemory, feature_vector
from .policy import (PolicyContext, final_plan, initial_plan, sar_required, settled, verdict_of)
from .tools import ToolBus

PATTERN_TEXT = {
    "card_testing": "card testing", "card_not_present_fraud": "card-not-present fraud",
    "card_not_present_new_device": "card-not-present fraud from a new device", "out_of_region_use": "out-of-region use",
    "account_takeover": "account takeover", "undocumented": "an undocumented pattern", "none": "no fraud",
}
RESPONSE_DELTA = {"deny": 1.8, "confirm": -3.2, "no_reply": 0.0}


def logit(p: float) -> float:
    return math.log(p / (1 - p))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def readable(text: str) -> str:
    """Narratives must not carry unexplained internal codes: replace device ids with their profile."""
    text = re.sub(r"Device(?: profile)? D\d{6} \(([^)]*)\)", r"device profile '\1'", text)
    return re.sub(r"\b[Dd]evice D\d{6}\b", "the device", text)


def shift(ts: str, **kw) -> str:
    return (datetime.fromisoformat(ts) + timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


class Investigation:
    def __init__(self, alert: dict, bus: ToolBus, kb, memory: CaseMemory, llm: LLM, emit: Callable[[dict], None]):
        self.alert, self.bus, self.kb, self.memory, self.llm, self.emit = alert, bus, kb, memory, llm, emit
        self.signals: list[D.Signal] = []
        self.docs: list[dict] = []
        self.tokens = 0
        self.step = 0
        self.prior = self._prior()
        self.x = logit(self.prior)
        self.history: list[dict] = []

    # ------------------------------------------------------------------ probability bookkeeping
    def _prior(self) -> float:
        a = self.alert
        if a["trigger_type"] == "customer_report":
            return 0.75   # closed history: every customer-reported case was confirmed, but disputes can be legitimate (R7)
        if a["trigger_type"] == "analyst_request":
            return 0.40
        score = float(a.get("risk_score") or 0.5)
        return sigmoid(logit(0.20) + 1.2 * (score - 0.5))  # score is a reason to look: shifts the prior, never decides

    @property
    def p(self) -> float:
        return sigmoid(self.x)

    def add(self, sig: D.Signal | None):
        if sig is None:
            return
        self.signals.append(sig)
        self.x += sig.weight
        self.emit({"type": "evidence", "step": self.step, "key": sig.key, "group": sig.group, "weight": sig.weight,
                   "claim": sig.claim, "ref": sig.ref, "p": round(self.p, 3)})

    def support(self, direction: int) -> int:
        return len({s.group for s in self.signals if s.weight * direction > 0.25})

    def is_settled(self) -> bool:
        return settled(self.p, self.support(1 if self.p >= 0.5 else -1))

    def mark(self, label: str):
        self.step += 1
        self.history.append({"step": self.step, "label": label, "p": round(self.p, 3)})
        self.emit({"type": "step", "step": self.step, "label": label, "p": round(self.p, 3), "settled": self.is_settled()})

    def sig(self, key: str) -> D.Signal | None:
        return next((s for s in self.signals if s.key == key), None)


class Tigra:
    def __init__(self, store, kb, memory: CaseMemory, llm: LLM | None = None):
        self.store, self.kb, self.memory, self.llm = store, kb, memory, llm or LLM()

    def investigate(self, case_id: str | None = None, alert: dict | None = None,
                    emit: Callable[[dict], None] | None = None, write: bool = True) -> dict:
        t_start = time.perf_counter()
        emit = emit or (lambda e: None)
        bus = ToolBus(self.store, self.kb, self.memory, emit)
        if alert is None:
            alert = bus.call("get_alert", lambda a: f"{a['trigger_type']} alert on {a['card_id']}", case_id=case_id)
            if alert is None:
                raise KeyError(f"unknown case {case_id}")
        inv = Investigation(alert, bus, self.kb, self.memory, self.llm, emit)
        emit({"type": "start", "case_id": alert["case_id"], "trigger": alert["trigger_type"], "text": alert["trigger_text"],
              "prior": round(inv.prior, 3)})

        # 1-2. Trigger + baseline --------------------------------------------------------------
        flag = bus.call("get_transaction", lambda t: f"${t['amt']} {t['channel']} product {t['product']} at {t['ts']}",
                        txn_id=int(alert["flagged_txn_id"]))
        if flag is None:
            raise KeyError(f"flagged transaction {alert['flagged_txn_id']} not found")
        card, cust, t0 = flag["card_id"], flag["customer_id"], flag["ts"]
        if alert["trigger_type"] == "customer_report":
            inv.signals.append(D.Signal("customer_denial", "customer", 0.0, f"Customer {cust} states they did not make the "
                                        f"${flag['amt']:,.2f} purchase (transaction {flag['txn_id']})", f"trigger:{alert['case_id']}",
                                        [cust, str(flag["txn_id"])], source="customer"))
        inv.mark("Trigger received; draft case opened")

        # Baseline stops where the episode window starts, so a spree cannot inflate its own baseline.
        w0 = shift(t0, hours=-96)
        prof = bus.call("card_profile", lambda p: f"{p['n']} txns before {w0[:10]}, median ${p['amt_median'] or 0:,.2f}", card_id=card, before_ts=w0)
        window = bus.call("card_window", lambda w: f"{len(w)} txns within ±96h", card_id=card, start_ts=w0, end_ts=shift(t0, hours=96))
        email_seen = (bus.call("email_seen_on_card", lambda s: f"{flag['p_email']} seen {s['n']}x", card_id=card,
                               email=flag["p_email"], before_ts=w0) if flag.get("p_email") else None)
        for s in (D.amount_signal(flag, prof), D.product_signal(flag, prof), D.card_testing(flag, window),
                  D.structuring(flag, window), D.email_ato_signal(flag, prof, window, email_seen),
                  D.spend_spike(flag, prof, window)):
            inv.add(s)
        if email_seen is not None and email_seen["n"] == 0 and (prof.get("n") or 0) >= 20 and flag["p_email"] != "anonymous.com" \
                and not inv.sig("mixed_channel_email"):
            same = [t for t in window if t["p_email"] == flag["p_email"]
                    and abs(datetime.fromisoformat(t["ts"]) - datetime.fromisoformat(t0)) <= timedelta(hours=24)]
            inv.add(D.Signal("new_email", "email", 0.3, f"Purchaser email domain {flag['p_email']} never appeared on this card before"
                             + (f"; it was used on {len(same)} purchases within 24 hours" if len(same) > 1 else ""),
                             f"query:email_seen_on_card(card_id={card})", [str(t["txn_id"]) for t in same] or [str(flag["txn_id"])],
                             data={"affected": same} if len(same) > 1 else {}))
        inv.mark("Card baseline and transaction window analysed")

        # 3. Hypothesis-driven evidence gathering ------------------------------------------------
        new_devices: set[str] = set()
        nb = None
        if flag.get("device_id"):
            seen = bus.call("device_seen_on_card", lambda s: f"seen {s['n']}x before", card_id=card, device_id=flag["device_id"], before_ts=t0)
            nb = bus.call("device_neighbors", lambda n: f"{n['device']['n_cards']} cards lifetime, "
                          f"{len({t['card_id'] for t in n['window_txns']})} in ±14d, {len(n['closed_cases'])} closed cases",
                          device_id=flag["device_id"], center_ts=t0, days=14)
            if seen["n"] == 0:
                new_devices.add(flag["device_id"])
            for s in D.device_novelty(flag, seen, nb["device"]):
                inv.add(s)
            inv.add(D.device_ring(flag, nb))
            inv.add(D.burst_signal(flag, prof, window, new_devices))
            inv.mark("Device and identity signals examined")
        if flag["channel"] == "in_person" and flag.get("addr1") is not None:
            hist = bus.call("region_history", lambda h: f"{h['n']} earlier txns in region", card_id=card, region=flag["addr1"], before_ts=t0)
            inv.add(D.region_signal(flag, hist, window))
            inv.mark("Billing-region behaviour examined")

        if not inv.is_settled() or alert["trigger_type"] == "customer_report":
            rec = bus.call("amount_recurrence", lambda r: f"{len(r['hits'])} similar earlier charges", card_id=card,
                           txn_id=int(flag["txn_id"]), amt=float(flag["amt"]), product=flag["product"], region=flag.get("addr1"))
            inv.add(D.recurrence_signal(flag, rec))
            inv.mark("Recurring-charge check")

        priors = bus.call("prior_cases", lambda c: f"{len(c)} prior cases for customer", customer_id=cust, before_ts=alert["opened_at"])
        episode = self._episode(inv, flag)
        ep_vec = self._vector(episode, flag)
        # Only distinctive device profiles link cases: a profile shared by hundreds of cards (or with no fields) is noise.
        distinctive = bool(nb and nb["device"]["n_cards"] <= 150 and not (nb["device"]["profile"] or "").startswith("? | ? | ? | ?"))
        devices = {flag["device_id"]} if distinctive else set()
        similar = bus.call("similar_cases", lambda s: ", ".join(f"{x['case_id']}({x['outcome'][:5]})" for x in s[:5]),
                           vec=ep_vec, card_id=card, customer_id=cust, devices=devices, before_ts=alert["opened_at"], k=5,
                           fraud_only=alert["trigger_type"] == "customer_report")
        inv.add(D.memory_signal(similar))
        inv.mark("Case memory consulted")

        pattern = self._pattern(inv, flag)
        hits = bus.call("kb_search", lambda d: ", ".join(x["title"][:40] for x in d),
                        query=f"{PATTERN_TEXT[pattern]} {flag['channel']} {alert['trigger_type'].replace('_', ' ')} policy action", k=3)
        inv.docs = hits
        inv.mark("Policy and typology passages retrieved (GraphRAG)")

        # 4-6. Assess, request evidence, act ------------------------------------------------------
        ring, struct = inv.sig("device_ring"), inv.sig("structuring")
        ct = inv.sig("card_testing")
        connected = sorted(set(ring.data["connected_cards"])) if ring else []
        shared = f"device profile {ring.data['profile']}" if ring else ""
        affected = self._affected(inv, flag)
        exposure = round(sum(abs(t["amt"]) for t in affected), 2)
        undocumented = pattern == "undocumented"
        strong_legit = any(s.weight <= -0.8 for s in inv.signals)
        conflicts = strong_legit and (any(s.weight >= 0.8 for s in inv.signals) or alert["trigger_type"] == "customer_report")
        recurring = inv.sig("recurring") is not None and alert["trigger_type"] == "customer_report"
        other_card_fraud = bool(ring and ring.data["closed_cases"])

        def ctx(p: float) -> PolicyContext:
            return PolicyContext(trigger=alert["trigger_type"], p=p, n_fraud_groups=inv.support(1), pattern=pattern,
                                 exposure=exposure, flagged_amt=flag["amt"], shared_origin=shared, connected_cards=connected,
                                 undocumented=undocumented, recurring_dispute=recurring,
                                 card_testing_big_cleared=bool(ct and ct.data["big_cleared"]), conflicts=conflicts,
                                 other_card_fraud=other_card_fraud)

        request = self._choose_request(inv, alert, pattern, recurring)
        p_initial = inv.p
        init = initial_plan(ctx(p_initial), request)
        emit({"type": "actions", "stage": "initial", "p": round(p_initial, 3), "actions": init.to_list()})

        evidence_requests, response = [], None
        if request:
            response, assumed = self._simulate(inv, request, recurring)
            inv.step += 1
            evidence_requests.append({"type": request, "asked_after_step": inv.step - 1, "assumed_response": assumed})
            emit({"type": "request", "request": request, "assumed_response": assumed, "response": response})
            inv.x += RESPONSE_DELTA[response]
            inv.signals.append(D.Signal(f"response_{response}", "customer", RESPONSE_DELTA[response], assumed,
                                        "evidence_request:1", [cust], source="customer"))
            inv.mark(f"Evidence request answered ({response.replace('_', ' ')})")
            if response == "confirm":
                pattern, affected, exposure = "none", [], 0.0

        p_final = inv.p
        final_ctx = ctx(p_final)
        final_ctx.exposure = exposure
        fin = final_plan(final_ctx, response, init)
        verdict = "legitimate" if response == "confirm" else verdict_of(p_final)
        if response == "deny" and verdict == "uncertain":
            verdict = "fraud" if p_final >= 0.6 else "uncertain"
        if verdict == "legitimate":
            pattern, affected, exposure = "none", [], 0.0
        final_list = fin.to_list()
        emit({"type": "actions", "stage": "final", "p": round(p_final, 3), "actions": final_list})

        # 7. Explain --------------------------------------------------------------------------------
        file_sar = any(a["action"] == "FILE_REPORT" for a in final_list)
        final_ctx.exposure = exposure
        if file_sar:   # FILE_REPORT is in the final actions: cite the 3a criteria that triggered it
            sar_reason = sar_required(final_ctx, "fraud")[1]
        else:
            needed, sar_reason = sar_required(final_ctx, verdict)
            if needed:  # criteria would apply, but fraud is not yet established (no reply / pending verification)
                sar_reason = "3a: not filed yet. Report criteria may apply but fraud is not established; revisit when verification completes."
        status = self._status(verdict, final_list, response)
        case_ref = f"CASE-{alert['case_id']}"
        evidence = self._evidence(inv, similar, request, response)
        similar_ids = [s["case_id"] for s in similar if s["case_id"].startswith("CC-")]
        linked_prior = [c["case_id"] for c in priors if c["source"] == "closed_case"][-3:]
        similar_ids = list(dict.fromkeys(similar_ids + [c for c in linked_prior if c not in similar_ids]))[:6]
        for c in (ring.data["closed_cases"] if ring else []):
            if c["case_id"] not in similar_ids:
                similar_ids.append(c["case_id"])
        first = min(affected, key=lambda t: (t["ts"], t["txn_id"]))["txn_id"] if affected else ""
        pattern_desc = self._pattern_description(pattern, inv, connected, flag) if pattern == "undocumented" else ""

        answer = {
            "case_id": alert["case_id"],
            "case": {
                "status": status, "verdict": verdict, "fraud_probability": round(p_final, 2), "pattern": pattern,
                "pattern_description": pattern_desc,
                "affected_txn_ids": [str(t["txn_id"]) for t in sorted(affected, key=lambda t: (t["ts"], t["txn_id"]))],
                "first_suspicious_txn_id": str(first) if first else "",
                "connected_card_ids": connected if verdict != "legitimate" else [],
                "connected_device_profiles": [ring.data["profile"]] if ring and verdict != "legitimate" else [],
                "exposure_usd": exposure, "evidence": evidence, "similar_prior_cases": similar_ids,
                "summary": "", "written_to_graph": False, "graph_case_id": "",
            },
            "evidence_requests": evidence_requests,
            "next_best_actions": {"initial": init.to_list(), "final": final_list,
                                  "what_changed": self._what_changed(init.to_list(), final_list, p_initial, p_final, response)},
            "sar": {"file": file_sar, "reason": sar_reason,
                    "narrative": "", "subjects": [], "total_amount_usd": 0, "activity_dates": []},
            "stop_reason": self._stop_reason(inv, response, p_final),
            "tool_calls": 0, "tokens": 0, "latency_s": 0.0,
        }
        if file_sar:
            answer["sar"].update(self._sar(alert, flag, affected, exposure, pattern, connected, ring, struct, inv, response))
        self._narrate(answer, inv, flag, similar)

        # 8. Remember ------------------------------------------------------------------------------
        if write:
            rec = {"graph_case_id": case_ref, "case_id": alert["case_id"], "card_id": card, "customer_id": cust,
                   "opened_at": alert["opened_at"], "status": status, "verdict": verdict, "pattern": pattern,
                   "fraud_probability": round(p_final, 3), "exposure_usd": exposure, "summary": answer["case"]["summary"],
                   "sar_filed": file_sar, "txn_ids": answer["case"]["affected_txn_ids"] or [str(flag["txn_id"])],
                   "connected_card_ids": answer["case"]["connected_card_ids"], "device_ids": sorted(devices),
                   "actions": [a["action"] for a in final_list], "updated_at": datetime.utcnow().isoformat(timespec="seconds"),
                   "vec": [round(float(v), 5) for v in ep_vec]}
            bus.call("write_case", lambda r: f"FraudCase {r} upserted", rec=rec)
            self.memory.add(rec, ep_vec)
            answer["case"]["written_to_graph"] = True
            answer["case"]["graph_case_id"] = case_ref
        answer["tool_calls"] = bus.calls
        answer["tokens"] = inv.tokens
        answer["latency_s"] = round(time.perf_counter() - t_start, 2)
        emit({"type": "done", "answer": answer, "history": inv.history})
        return answer

    # ---------------------------------------------------------------------- reasoning helpers
    @staticmethod
    def _episode(inv: Investigation, flag: dict) -> list[dict]:
        seen, out = set(), []
        for s in inv.signals:
            for t in s.data.get("affected", []):
                if t["txn_id"] not in seen:
                    seen.add(t["txn_id"]); out.append(t)
        if flag["txn_id"] not in seen:
            out.append(flag)
        return out

    def _affected(self, inv: Investigation, flag: dict) -> list[dict]:
        """Fraud episode: the strongest structural detector defines the scope; weaker bursts only add to plain CNP."""
        for key in ("structuring", "card_testing", "device_ring", "mixed_channel_email", "mixed_channel_spike",
                    "out_of_region", "cnp_burst", "new_email"):
            s = inv.sig(key)
            if s and s.data.get("affected"):
                eps = {t["txn_id"]: t for t in s.data["affected"]}
                eps.setdefault(flag["txn_id"], flag)
                return list(eps.values())
        return [flag]

    @staticmethod
    def _vector(episode: list[dict], flag: dict):
        n = len(episode)
        tss = sorted(datetime.fromisoformat(t["ts"]) for t in episode)
        return feature_vector(sum(t["channel"] == "online" for t in episode) / n,
                              sum(t.get("device_status") == "New" for t in episode) / n,
                              sum(bool(t.get("proxy")) for t in episode) / n,
                              min(t["amt"] for t in episode), max(t["amt"] for t in episode), n,
                              (tss[-1] - tss[0]).total_seconds() / 60, flag["product"])

    @staticmethod
    def _pattern(inv: Investigation, flag: dict) -> str:
        if inv.p < 0.3 and inv.alert["trigger_type"] != "customer_report":
            return "none"
        if inv.sig("structuring") or inv.sig("device_ring"):
            return "undocumented"
        if inv.sig("card_testing"):
            return "card_testing"
        if inv.sig("mixed_channel_email") or inv.sig("mixed_channel_spike"):
            return "account_takeover"
        if inv.sig("out_of_region"):
            return "out_of_region_use"
        if flag["channel"] == "online":
            if inv.sig("new_device") and (flag.get("device_status") == "New" or inv.sig("proxy")):
                return "card_not_present_new_device"
            return "card_not_present_fraud"
        # card-present with no region/credential anomaly: no documented pattern is supported by the evidence
        return "account_takeover" if inv.sig("new_email") and inv.p >= 0.7 else "none"

    @staticmethod
    def _choose_request(inv: Investigation, alert: dict, pattern: str, recurring: bool) -> str | None:
        if recurring:
            return "customer_validation"
        if alert["trigger_type"] == "customer_report" or inv.is_settled():
            return None
        if pattern == "card_testing":
            return "step_up_auth"
        return "customer_validation"

    @staticmethod
    def _simulate(inv: Investigation, request: str, recurring: bool) -> tuple[str, str]:
        """Replies are not provided by the dataset: simulate the most likely reply given the evidence and say so."""
        p = inv.p
        who = "Cardholder" if request == "customer_validation" else "Step-up challenge"
        if recurring:
            return "confirm", ("Assumed: cardholder recognises the charge as their own recurring subscription once shown "
                               "the earlier identical charges (simulated; the dataset provides no replies)")
        if p >= 0.6:
            return "deny", (f"Assumed: {who.lower()} {'denies making the transaction and still has the card' if request == 'customer_validation' else 'fails; the cardholder does not recognise the activity'} "
                            f"(simulated from evidence posterior {p:.2f})")
        if p <= 0.4:
            return "confirm", (f"Assumed: {who.lower()} {'confirms the purchase as their own' if request == 'customer_validation' else 'passes with the registered device'} "
                               f"(simulated from evidence posterior {p:.2f})")
        return "no_reply", (f"Assumed: no reply within 24 hours; evidence posterior {p:.2f} is too balanced to presume an answer (simulated)")

    @staticmethod
    def _status(verdict: str, actions: list[dict], response: str | None) -> str:
        names = {a["action"] for a in actions}
        if verdict == "legitimate":
            return "closed_legitimate"
        if "ESCALATE_TO_ANALYST" in names:
            return "escalated"
        if verdict == "fraud":
            return "closed_fraud"
        return "open"

    def _evidence(self, inv: Investigation, similar: list[dict], request: str | None, response: str | None) -> list[dict]:
        import re
        ev = []
        for s in sorted(inv.signals, key=lambda s: -abs(s.weight) if s.source == "graph" else 0):
            e = s.as_evidence()
            e["entity_ids"] = [x for x in e["entity_ids"] if not re.fullmatch(r"D\d{6}", x)]  # device ids are internal
            ev.append(e)
        for d in inv.docs[:2]:
            ev.append({"claim": f"Policy/typology grounding: {d['title']}", "source": "document", "ref": d["doc_id"], "entity_ids": []})
        return ev

    @staticmethod
    def _what_changed(init: list[dict], final: list[dict], p0: float, p1: float, response: str | None) -> str:
        a0, a1 = [a["action"] for a in init], [a["action"] for a in final]
        if response is None or a0 == a1:
            return "nothing"
        added, dropped = [a for a in a1 if a not in a0], [a for a in a0 if a not in a1]
        why = {"deny": "The assumed customer denial", "confirm": "The assumed customer confirmation",
               "no_reply": "No reply within 24 hours"}[response]
        return (f"{why} moved fraud probability from {p0:.2f} to {p1:.2f}. "
                + (f"Added {', '.join(added)}" if added else "") + ("; " if added and dropped else "")
                + (f"dropped {', '.join(dropped)}" if dropped else "") + ".")

    @staticmethod
    def _stop_reason(inv: Investigation, response: str | None, p: float) -> str:
        if response == "confirm":
            return "Verification settled the question: the cardholder confirmed the activity (R3). Further graph steps would not change the decision."
        if response == "deny":
            return f"Verification settled the question: denial raised probability to {p:.2f}; actions follow R2. Further steps would not change them."
        if response == "no_reply":
            return "No reply within 24 hours (R4); the case stays open with monitoring. Further graph queries cannot resolve the remaining uncertainty without the customer."
        n = inv.support(1 if p >= 0.5 else -1)
        if inv.alert["trigger_type"] == "customer_report":
            return f"Customer denial plus {n} independent graph evidence group(s) support the decision at probability {p:.2f}; further steps would not change the R2 actions."
        return f"Section 6 stopping rule met: probability {p:.2f} backed by {n} independent evidence groups."

    # ---------------------------------------------------------------------- text generation
    def _pattern_description(self, pattern: str, inv: Investigation, connected: list[str], flag: dict) -> str:
        st, ring = inv.sig("structuring"), inv.sig("device_ring")
        if st:
            return (f"Threshold structuring: {len(st.data['affected'])} online purchases on {flag['card_id']} within "
                    f"{st.data['minutes']} minutes, each just under $500, apparently sized to stay below a $500 authorization "
                    f"review threshold. Found by scanning the card's transaction window for clusters of near-threshold "
                    f"amounts; the same shape appears in closed undocumented cases (four purchases just under $500 in forty minutes).")
        if ring:
            return (f"Device-sharing ring: one device profile ({ring.data['profile']}) placed online purchases on "
                    f"{len(connected) + 1} unrelated customers' cards within a few weeks, "
                    + ("always flagged New and behind an anonymous proxy. " if ring.data["anon_new"] >= 0.8 else
                       "with near-identical amounts and contact details. ")
                    + "Found by traversing Device -> Transaction -> Card for the flagged device; per-card history alone looks ordinary.")
        return ""

    def _sar(self, alert, flag, affected, exposure, pattern, connected, ring, struct, inv, response) -> dict:
        days = sorted(t["ts"][:10] for t in affected) or [flag["ts"][:10]]
        chans = sorted({t["channel"].replace("_", "-") for t in affected})
        how = {"undocumented": (inv.sig("structuring") and "a series of online purchases each sized just under $500 within minutes, consistent with structuring below an authorization threshold")
               or "online purchases from a single device profile shared across many unrelated cardholders, consistent with a coordinated ring",
               "card_testing": "small test authorizations followed by larger purchases, consistent with validating a stolen card number",
               "card_not_present_new_device": "card-not-present purchases from a device never before seen on the account",
               "card_not_present_fraud": "card-not-present purchases inconsistent with the cardholder's history",
               "out_of_region_use": "card-present purchases in a billing region with no prior history for the card",
               "account_takeover": "mixed-channel activity using credentials inconsistent with the cardholder"}[pattern]
        who = f"customer {flag['customer_id']}, card {flag['card_id']}"
        if connected:
            who += f", and {len(connected)} other card(s) linked by the same device profile ({', '.join(connected[:8])}{'...' if len(connected) > 8 else ''})"
        dev = f" The transactions came from device profile '{ring.data['profile']}'." if ring else ""
        resp = {"deny": " The cardholder, when contacted, denied making the transactions (simulated response).",
                None: " The cardholder reported the activity as unauthorized." if alert["trigger_type"] == "customer_report" else "",
                "no_reply": " The cardholder did not respond within 24 hours.", "confirm": ""}[response]
        txl = ", ".join(f"{t['txn_id']} (${t['amt']:,.2f}, {t['ts'][:16]})" for t in sorted(affected, key=lambda t: t["ts"])[:10])
        why = readable("; ".join(s.claim for s in sorted(inv.signals, key=lambda s: -s.weight) if s.weight > 0.3 and s.source == "graph"))[:900]
        narrative = (
            f"This report concerns {who}. Between {days[0]} and {days[-1]}, {len(affected)} {'/'.join(chans)} transaction(s) totaling "
            f"${exposure:,.2f} were identified as unauthorized: {txl}. The activity was detected through a "
            f"{alert['trigger_type'].replace('_', ' ')} ({alert['trigger_text'][:160]}).{resp}{dev} "
            f"The method of operation was {how}. It is suspicious because {why}. "
            f"The bank opened internal case CASE-{alert['case_id']}, recommended blocking the card, and placed "
            f"{'the linked cards under monitoring' if connected else 'the account under review'}. "
            f"Total suspicious amount: ${exposure:,.2f}.")
        subjects = [flag["customer_id"], flag["card_id"]] + connected + ([ring.data["profile"]] if ring else [])
        return {"narrative": narrative, "subjects": subjects, "total_amount_usd": exposure, "activity_dates": [days[0], days[-1]]}

    def _narrate(self, answer: dict, inv: Investigation, flag: dict, similar: list[dict]) -> None:
        c = answer["case"]
        direction = 1 if c["verdict"] == "fraud" else -1 if c["verdict"] == "legitimate" else 0
        # lead with the evidence that supports the verdict (uncertain: strongest either way)
        top = [s.claim for s in sorted(inv.signals, key=lambda s: -(s.weight * direction if direction else abs(s.weight)))
               if abs(s.weight) >= 0.4 and s.source == "graph"][:3]
        fa = answer["next_best_actions"]["final"]
        template = (f"{inv.alert['trigger_type'].replace('_', ' ').capitalize()} on {flag['card_id']} for ${flag['amt']:,.2f} "
                    f"({flag['channel'].replace('_', ' ')}, product {flag['product']}). Verdict {c['verdict']} at probability "
                    f"{c['fraud_probability']:.2f}: {PATTERN_TEXT[c['pattern']]}. Key evidence: " + " | ".join(top or ["no strong signal beyond the trigger"])
                    + f". Next: {', '.join(a['action'] for a in fa)}.")
        c["summary"] = readable(template)
        if not self.llm.enabled:
            return
        ctx = {"alert": inv.alert, "flagged_txn": {k: flag[k] for k in ("txn_id", "ts", "amt", "product", "channel", "addr1", "device_profile") if k in flag},
               "verdict": c["verdict"], "probability": c["fraud_probability"], "pattern": c["pattern"], "exposure": c["exposure_usd"],
               "evidence": [e["claim"] for e in c["evidence"]][:12], "policy_passages": [d["text"][:400] for d in inv.docs],
               "similar_cases": [{k: s[k] for k in ("case_id", "outcome", "pattern", "notes")} for s in similar[:4]],
               "final_actions": fa, "evidence_requests": answer["evidence_requests"],
               "draft_sar": answer["sar"]["narrative"]}
        want = '{"summary": "2-6 sentences"' + (', "sar_narrative": "6-12 sentences: who, what, when, where, how, why"' if answer["sar"]["file"] else "") \
               + (', "pattern_description": "2-3 sentences"' if c["pattern"] == "undocumented" else "") + "}"
        out, tok = self.llm.complete_json(f"Case context (GraphRAG):\n{ctx}\n\nReturn JSON exactly like {want}. Keep every ID and amount identical to the context.")
        inv.tokens += tok
        if out:
            c["summary"] = out.get("summary") or c["summary"]
            if answer["sar"]["file"] and out.get("sar_narrative"):
                answer["sar"]["narrative"] = out["sar_narrative"]
            if c["pattern"] == "undocumented" and out.get("pattern_description"):
                c["pattern_description"] = out["pattern_description"]
