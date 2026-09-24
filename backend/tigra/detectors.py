"""Pattern detectors. Each is a pure function over graph-tool outputs that returns Signals.

A Signal is one piece of evidence: a claim, the query it came from, the entity ids it rests on, a log-odds weight
(positive = towards fraud) and an independence group (the section 6 stopping rule needs >= 2 independent pieces).
Weights are deliberately coarse and were sanity-checked against the closed-case history; the risk score itself is
only used in the prior, never as a verdict.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class Signal:
    key: str
    group: str
    weight: float
    claim: str
    ref: str
    entity_ids: list = field(default_factory=list)
    source: str = "graph"
    data: dict = field(default_factory=dict)

    def as_evidence(self) -> dict:
        return {"claim": self.claim, "source": self.source, "ref": self.ref, "entity_ids": [str(e) for e in self.entity_ids]}


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def money(x: float) -> str:
    return f"${x:,.2f}"


def _tid(t: dict) -> str:
    return str(t["txn_id"])


# ---------------------------------------------------------------------------- sequence patterns
def card_testing(flag: dict, window: list[dict]) -> Signal | None:
    """>=3 tiny (<$5) online authorizations within 60 min, then a larger online purchase within 24h (pattern 1 / R5)."""
    small = [t for t in window if t["channel"] == "online" and t["amt"] < 5]
    for i in range(len(small)):
        run = [t for t in small[i:] if ts(t["ts"]) - ts(small[i]["ts"]) <= timedelta(minutes=60)]
        if len(run) < 3:
            continue
        end = ts(run[-1]["ts"])
        big = [t for t in window if t["channel"] == "online" and t["amt"] >= 20
               and end < ts(t["ts"]) <= end + timedelta(hours=24)]
        # the alert must sit inside the sequence (flagged tiny auth or flagged follow-up purchase)
        ids = {_tid(t) for t in run + big}
        if big and _tid(flag) in ids:
            aff = run + big
            return Signal("card_testing", "sequence", 3.0,
                          f"{len(run)} online authorizations under $5 within {int((end - ts(run[0]['ts'])).seconds / 60)} minutes "
                          f"followed by {len(big)} larger online purchase(s) up to {money(max(t['amt'] for t in big))}",
                          f"query:card_window(card_id={flag['card_id']})", [_tid(t) for t in aff],
                          data={"affected": aff, "big_cleared": any(t["amt"] > 100 for t in big)})
    return None


def structuring(flag: dict, window: list[dict]) -> Signal | None:
    """>=3 online purchases just under $500 inside 60 minutes: amounts chosen to stay under an authorization threshold."""
    near = [t for t in window if t["channel"] == "online" and 400 <= t["amt"] < 500]
    for i in range(len(near)):
        run = [t for t in near[i:] if ts(t["ts"]) - ts(near[i]["ts"]) <= timedelta(minutes=60)]
        if len(run) >= 3 and _tid(flag) in {_tid(t) for t in run}:
            mins = int((ts(run[-1]["ts"]) - ts(run[0]["ts"])).seconds / 60)
            devices = sorted({t["device_id"] for t in run if t["device_id"]})
            return Signal("structuring", "sequence", 3.2,
                          f"{len(run)} online purchases within {mins} minutes, each just under $500 "
                          f"({', '.join(money(t['amt']) for t in run)}), total {money(sum(t['amt'] for t in run))}",
                          f"query:card_window(card_id={flag['card_id']})", [_tid(t) for t in run] + devices,
                          data={"affected": run, "devices": devices, "minutes": mins})
    return None


# ---------------------------------------------------------------------------- network patterns
def device_ring(flag: dict, nb: dict) -> Signal | None:
    """Rare device profile used by >=3 cards in a short window with homogeneous behaviour (R6 shared origin)."""
    dev, life, win = flag.get("device_id"), nb["device"], nb["window_txns"]
    if not dev or life["n_cards"] > 80 or "? | ? | ? | ?" in (life.get("profile") or ""):
        return None
    others = sorted({t["card_id"] for t in win if t["card_id"] != flag["card_id"]})
    if len(others) < 2:
        return None
    n = len(win)
    anon_new = sum(1 for t in win if t["device_status"] == "New" and (t["proxy"] or "").endswith(("ANONYMOUS", "HIDDEN"))) / n
    amts = [t["amt"] for t in win]
    cv = statistics.pstdev(amts) / statistics.mean(amts) if len(amts) > 1 else 0
    same_prod = max(sum(1 for t in win if t["product"] == p) for p in {t["product"] for t in win}) / n
    pairs = [(t["p_email"], t["r_email"]) for t in win if t["p_email"]]
    same_email = (max(pairs.count(p) for p in set(pairs)) / n) if pairs else 0
    traits = []
    if anon_new >= 0.8:
        traits.append(f"{anon_new:.0%} of its transactions are flagged New device behind an anonymous/hidden proxy")
    if same_prod >= 0.9 and cv <= 0.12:
        traits.append(f"near-identical amounts (mean {money(statistics.mean(amts))}, variation {cv:.0%}) on one product code")
    if same_email >= 0.8:
        traits.append(f"the same purchaser/recipient email pair {pairs[0][0]} / {pairs[0][1]} on {same_email:.0%} of them")
    if not traits:
        return None
    fraud_cases = [c for c in nb["closed_cases"] if c["outcome"] == "confirmed_fraud"]
    w = 2.6 + (0.6 if fraud_cases else 0)
    own = [t for t in win if t["card_id"] == flag["card_id"]]
    claim = (f"Device profile {dev} ({life['profile']}) was used by {len(others) + 1} different cards within "
             f"±{nb['window_days']} days; " + "; ".join(traits))
    if fraud_cases:
        claim += f". The same profile appears on {len(fraud_cases)} closed confirmed-fraud case(s): " + ", ".join(c["case_id"] for c in fraud_cases[:6])
    return Signal("device_ring", "network", w, claim, f"query:device_neighbors(device_id={dev}, days={nb['window_days']})",
                  [dev] + others[:25] + [c["case_id"] for c in fraud_cases[:6]],
                  data={"affected": own, "connected_cards": others, "profile": life["profile"], "closed_cases": fraud_cases,
                        "anon_new": anon_new, "cv": cv})


def device_novelty(flag: dict, seen: dict | None, life: dict | None) -> list[Signal]:
    out = []
    if not flag.get("device_id") or seen is None or (flag.get("device_profile") or "").startswith("? | ? | ? | ?"):
        return out  # a profile with no device/OS/browser/screen carries no identity information
    generic = (life or {}).get("n_cards", 0) > 150 or "? | ? | ? | ?" in (flag.get("device_profile") or "")
    ref = f"query:device_seen_on_card(card_id={flag['card_id']}, device_id={flag['device_id']})"
    if seen["n"] == 0:
        w = 0.35 if generic else 0.7
        out.append(Signal("new_device", "device", w,
                          f"Device {flag['device_id']} ({flag['device_profile']}) had never been used on {flag['card_id']} before; "
                          f"Vesta identity flag id_15 = {flag['device_status'] or 'missing'}"
                          + (" (common profile shared by many cards, so weak evidence)" if generic else ""),
                          ref, [flag["device_id"], flag["card_id"]]))
    elif seen["first_ts"] and ts(seen["first_ts"]) < ts(flag["ts"]) - timedelta(days=7):
        out.append(Signal("known_device", "device", -0.8,
                          f"Device {flag['device_id']} was already used {seen['n']} time(s) on this card since {seen['first_ts'][:10]}",
                          ref, [flag["device_id"], flag["card_id"]]))
    proxy = flag.get("proxy") or ""
    if proxy.endswith(("ANONYMOUS", "HIDDEN")):
        out.append(Signal("proxy", "device", 0.5, f"Connection went through a {proxy.split(':')[-1].lower()} proxy (id_23)",
                          f"query:get_transaction(txn_id={flag['txn_id']})", [_tid(flag)]))
    return out


# ---------------------------------------------------------------------------- behavioural anomalies
def amount_signal(flag: dict, prof: dict) -> Signal | None:
    if (prof.get("n") or 0) < 5:
        return None
    a, mx, p95, p25, p75 = flag["amt"], prof["amt_max"], prof["amt_p95"], prof["amt_p25"], prof["amt_p75"]
    ref = f"query:card_profile(card_id={flag['card_id']})"
    base = f"(card history: {prof['n']} txns, median {money(prof['amt_median'])}, 95th pct {money(p95)}, max {money(mx)})"
    if a > 1.5 * mx:
        return Signal("amount_far_above", "amount", 1.2, f"Flagged {money(a)} is {a / mx:.1f}x the largest amount this card ever spent {base}", ref, [_tid(flag)])
    if a > mx:
        return Signal("amount_above_max", "amount", 0.8, f"Flagged {money(a)} exceeds every earlier amount on the card {base}", ref, [_tid(flag)])
    if a > p95:
        return Signal("amount_high", "amount", 0.4, f"Flagged {money(a)} is above the card's 95th percentile {base}", ref, [_tid(flag)])
    if p25 <= a <= p75 * 1.5:
        return Signal("amount_typical", "amount", -0.4, f"Flagged {money(a)} is a typical amount for this card {base}", ref, [_tid(flag)])
    return None


def product_signal(flag: dict, prof: dict) -> Signal | None:
    if (prof.get("n") or 0) < 10:
        return None
    used = {p["product"]: p["n"] for p in prof["products"]}
    ref = f"query:card_profile(card_id={flag['card_id']})"
    if flag["product"] not in used:
        return Signal("new_product", "product", 0.6,
                      f"Product code {flag['product']} was never used on this card before (history: "
                      + ", ".join(f"{k}={v}" for k, v in used.items()) + ")", ref, [_tid(flag)])
    return None


def region_signal(flag: dict, hist: dict | None, window: list[dict]) -> Signal | None:
    """Pattern 4. Card-present purchase in a billing region with no history, while home activity continues."""
    if flag["channel"] != "in_person" or flag["addr1"] is None or hist is None:
        return None
    r, t0 = flag["addr1"], ts(flag["ts"])
    ref = f"query:region_history(card_id={flag['card_id']}, region={r})"
    if hist["n"] == 0:
        days = {t["ts"][:10] for t in window if t["addr1"] == r and t["channel"] == "in_person"
                and t0 - timedelta(days=2) <= ts(t["ts"]) <= t0 + timedelta(days=7)}
        home = [t for t in window if t["channel"] == "in_person" and t["addr1"] not in (None, r)
                and abs(ts(t["ts"]) - t0) <= timedelta(hours=24)]
        if len(days) >= 3:
            return Signal("trip", "region", -1.2, f"Region {r:g} is new for the card but it was used there on {len(days)} separate days: a trip, not a clone (pattern 4 note)",
                          ref, [_tid(flag)])
        in_region = [t for t in window if t["addr1"] == r and t["channel"] == "in_person" and abs(ts(t["ts"]) - t0) <= timedelta(hours=48)]
        return Signal("out_of_region", "region", 1.3 if home else 0.8,
                      f"Card-present purchase in billing region {r:g}, where this card has no history"
                      + (f", while {len(home)} purchase(s) continued in its usual regions within 24 hours" if home else ""),
                      ref, [_tid(t) for t in in_region] + [_tid(t) for t in home[:3]], data={"affected": in_region})
    if hist["n"] >= 10 and ts(hist["first_ts"]) < t0 - timedelta(days=30):
        return Signal("familiar_region", "region", -0.8,
                      f"Region {r:g} is familiar: {hist['n']} earlier purchases on {hist['days']} days since {hist['first_ts'][:10]}", ref, [_tid(flag)])
    if hist["n"] >= 1:
        return Signal("known_region", "region", -0.3, f"Region {r:g} was used {hist['n']} time(s) before on this card", ref, [_tid(flag)])
    return None


def recurrence_signal(flag: dict, rec: dict) -> Signal | None:
    """Same product (and region, card-present) at the same amount repeatedly: the cardholder's own recurring pattern (R7)."""
    hits = rec["hits"]
    days = sorted({ts(h["ts"]).date() for h in hits})
    if len(days) < 3:
        return None
    span = (days[-1] - days[0]).days
    share = len(hits) / max(rec["scope_n"], 1)
    if span < 21 or share < 0.08:   # at least three weeks of history, and a real share of that product's use
        return None
    gaps = [(b - a).days for a, b in zip(days, days[1:])]
    cadence = statistics.median(gaps)
    kind = "weekly" if 5 <= cadence <= 9 else "monthly" if 25 <= cadence <= 35 else None
    if kind is None:  # same amount at irregular intervals is common pricing, not a subscription
        return None
    where = f" in region {flag['addr1']:g}" if flag["product"] == "W" and flag["addr1"] else ""
    return Signal("recurring", "recurrence", -1.9,
                  f"{len(hits)} earlier {kind} charges of ~{money(flag['amt'])} on product {flag['product']}{where} since {hits[0]['ts'][:10]} "
                  f"({share:.0%} of that product's history on this card): matches the cardholder's own recurring pattern",
                  f"query:amount_recurrence(card_id={flag['card_id']}, amt={flag['amt']})", [_tid(h) for h in hits[-6:]],
                  data={"cadence": kind, "n": len(hits)})


def email_ato_signal(flag: dict, prof: dict, window: list[dict], seen: dict | None) -> Signal | None:
    """Pattern 5 proxy. A purchaser email that is rare for the card, used across both channels in a short burst."""
    em = flag.get("p_email")
    if not em or seen is None or (prof.get("n") or 0) < 20:
        return None
    share = seen["n"] / prof["n"]
    if share >= 0.02:
        return None
    t0 = ts(flag["ts"])
    burst = [t for t in window if t["p_email"] == em and abs(ts(t["ts"]) - t0) <= timedelta(hours=96)]
    channels = {t["channel"] for t in burst}
    if len(burst) >= 3 and len(channels) == 2:
        return Signal("mixed_channel_email", "email", 1.1,
                      f"Purchaser email {em} (only {share:.1%} of this card's history) drove {len(burst)} purchases across both "
                      f"channels within 4 days ({', '.join(sorted(channels))}): mixed-channel use of the customer's credentials",
                      f"query:card_window(card_id={flag['card_id']})", [_tid(t) for t in burst], data={"affected": burst})
    return None


def spend_spike(flag: dict, base: dict, window: list[dict]) -> Signal | None:
    """Pattern 5. Several purchases far above the card's pre-window baseline within 48h, spanning both channels."""
    if (base.get("n") or 0) < 10:
        return None
    t0 = ts(flag["ts"])
    bar = max(base["amt_p95"], 3 * base["amt_median"])
    big = [t for t in window if t["amt"] > bar and abs(ts(t["ts"]) - t0) <= timedelta(hours=48)]
    if len(big) >= 3 and _tid(flag) in {_tid(t) for t in big} and len({t["channel"] for t in big}) == 2:
        return Signal("mixed_channel_spike", "sequence", 1.1,
                      f"{len(big)} purchases above the card's pre-alert 95th percentile ({money(bar)}) within 48 hours across both "
                      f"channels, total {money(sum(t['amt'] for t in big))}: activity inconsistent with the cardholder",
                      f"query:card_window(card_id={flag['card_id']})", [_tid(t) for t in big], data={"affected": big})
    return None


def burst_signal(flag: dict, prof: dict, window: list[dict], new_devices: set[str]) -> Signal | None:
    """Pattern 2 hallmark: 2-4 unusual online purchases within 48 hours."""
    if flag["channel"] != "online" or (prof.get("n") or 0) < 5:
        return None
    t0, p95 = ts(flag["ts"]), prof["amt_p95"]
    odd = [t for t in window if t["channel"] == "online" and abs(ts(t["ts"]) - t0) <= timedelta(hours=48)
           and (t["amt"] > p95 or (t["device_id"] and t["device_id"] in new_devices))]
    if 2 <= len(odd) <= 4 and _tid(flag) in {_tid(t) for t in odd}:
        return Signal("cnp_burst", "sequence", 0.6, f"{len(odd)} unusual online purchases within 48 hours "
                      f"(above the card's 95th percentile or from a device new to the card), total {money(sum(t['amt'] for t in odd))}",
                      f"query:card_window(card_id={flag['card_id']})", [_tid(t) for t in odd], data={"affected": odd})
    return None


def memory_signal(similar: list[dict]) -> Signal | None:
    """Case memory as evidence: a past confirmed-fraud case that shares a device with this activity."""
    labelled = [s for s in similar if s["outcome"] in ("confirmed_fraud", "cleared", "fraud", "legitimate")]
    linked = [s for s in labelled if s["link"] and s["outcome"] in ("confirmed_fraud", "fraud")
              and any(l.startswith("shared device") for l in s["link"])]
    if linked:
        return Signal("memory_linked_fraud", "memory", 0.6,
                      f"Past confirmed-fraud case(s) {', '.join(s['case_id'] for s in linked)} share a device with this activity",
                      "query:similar_cases", [s["case_id"] for s in linked])
    # Outcome shares of unlinked look-alikes are NOT used as evidence: in the history every cleared case was a model
    # alert and every customer report was confirmed, so their outcome mostly encodes the trigger type, not the facts.
    return None
