"""Fraud Policy v1.0 as code: action catalogue, approval routing (section 2), rules R1-R10, case-vs-report (3a).

The LLM never picks actions. Actions come from these rules, so every recommendation is reproducible and
cites the rule it came from. Only `auto` actions may be executed by the agent; L1/L2 wait for a human.
"""
from __future__ import annotations

from dataclasses import dataclass, field

AUTO = {"ALLOW_TRANSACTION", "MONITOR_CARD", "MONITOR_CONNECTED_CARDS", "WARN_CUSTOMER", "VERIFY_WITH_CUSTOMER",
        "STEP_UP_AUTH", "GENERATE_REPORT", "CREATE_CASE", "ESCALATE_TO_ANALYST", "CLOSE_NO_FRAUD"}
ACTIONS = AUTO | {"DECLINE_TRANSACTION", "BLOCK_CARD", "BLOCK_ALL_CARDS", "FILE_REPORT"}
APPROVER = {"auto": "TIGRA", "L1": "team lead", "L2": "fraud manager"}

# Execution order when several actions are recommended ("order them by what happens first").
ORDER = ["DECLINE_TRANSACTION", "STEP_UP_AUTH", "VERIFY_WITH_CUSTOMER", "BLOCK_CARD", "BLOCK_ALL_CARDS",
         "CREATE_CASE", "FILE_REPORT", "MONITOR_CARD", "MONITOR_CONNECTED_CARDS", "WARN_CUSTOMER",
         "ESCALATE_TO_ANALYST", "GENERATE_REPORT", "ALLOW_TRANSACTION", "CLOSE_NO_FRAUD"]


def route(action: str, exposure: float) -> str:
    if action in AUTO:
        return "auto"
    if action == "DECLINE_TRANSACTION":
        return "L1"
    if action == "BLOCK_CARD":
        return "L1" if exposure <= 2500 else "L2"
    return "L2"  # BLOCK_ALL_CARDS, FILE_REPORT


@dataclass
class PolicyContext:
    trigger: str                   # risk_score | customer_report | analyst_request
    p: float                       # fraud probability at decision time
    n_fraud_groups: int            # independent evidence groups pointing to fraud
    pattern: str
    exposure: float
    flagged_amt: float
    shared_origin: str = ""        # named shared element (device profile / region / email) when R6 applies
    connected_cards: list = field(default_factory=list)
    undocumented: bool = False
    recurring_dispute: bool = False
    card_testing_big_cleared: bool = False
    conflicts: bool = False
    other_card_fraud: bool = False  # links to another card's confirmed fraud (3a)
    fraud_cards_of_customer: int = 1
    credentials_compromised: bool = False


class Plan:
    """Ordered, de-duplicated action list with per-action rule citations."""

    def __init__(self, exposure: float):
        self.exposure = exposure
        self.items: dict[str, list[str]] = {}

    def add(self, action: str, reason: str) -> "Plan":
        assert action in ACTIONS, action
        self.items.setdefault(action, [])
        if reason not in self.items[action]:
            self.items[action].append(reason)
        return self

    def has(self, action: str) -> bool:
        return action in self.items

    def to_list(self) -> list[dict]:
        return [{"action": a, "route": route(a, self.exposure), "reason": "; ".join(self.items[a])}
                for a in sorted(self.items, key=ORDER.index)]


def verdict_of(p: float) -> str:
    return "fraud" if p >= 0.7 else "legitimate" if p <= 0.3 else "uncertain"


def settled(p: float, n_support: int) -> bool:
    """Section 6 stopping rule: >=0.85 or <=0.15 backed by at least two independent pieces of evidence."""
    return (p >= 0.85 or p <= 0.15) and n_support >= 2


def sar_required(ctx: PolicyContext, verdict: str) -> tuple[bool, str]:
    """Section 3a: fraud confirmed/strongly suspected AND (exposure > $1,000 OR shared/linked OR coordinated/undocumented)."""
    if verdict != "fraud":
        return False, "3a: no report. Fraud is not confirmed or strongly suspected."
    why = []
    if ctx.exposure > 1000:
        why.append(f"3a/R2: exposure ${ctx.exposure:,.2f} exceeds $1,000")
    if ctx.shared_origin:
        why.append(f"R6: activity connects to a shared {ctx.shared_origin}")
    if ctx.other_card_fraud and not ctx.shared_origin:
        why.append("3a: activity connects to another card's fraud")
    if ctx.undocumented:
        why.append("R9: coordinated/undocumented pattern")
    if why:
        return True, "Fraud strongly suspected and " + "; ".join(why) + "."
    return False, f"3a: fraud, but exposure ${ctx.exposure:,.2f} is not above $1,000 and there is no shared device, region cluster or coordinated pattern. Case only."


def fraud_actions(ctx: PolicyContext, plan: Plan, basis: str) -> Plan:
    """Actions once fraud is established (customer denial, or strong multi-signal evidence)."""
    exp = f"${ctx.exposure:,.2f}"
    if ctx.fraud_cards_of_customer >= 2 or ctx.credentials_compromised:
        plan.add("BLOCK_ALL_CARDS", "R10: two or more of the customer's cards show confirmed fraud")
    else:
        plan.add("BLOCK_CARD", f"{basis}; exposure {exp} {'is under' if ctx.exposure <= 2500 else 'exceeds'} $2,500 so route {route('BLOCK_CARD', ctx.exposure)}")
    if ctx.pattern == "card_testing":
        plan.add("DECLINE_TRANSACTION", "R5: decline pending authorizations in the testing sequence")
    plan.add("CREATE_CASE", basis.split(":")[0] + ": open/keep the fraud case with evidence attached (3a)")
    file, why = sar_required(ctx, "fraud")
    if file:
        plan.add("FILE_REPORT", why)
    if ctx.connected_cards:
        plan.add("MONITOR_CONNECTED_CARDS",
                 f"R6: {len(ctx.connected_cards)} other card(s) share the {ctx.shared_origin or 'linked element'}")
    if ctx.undocumented:
        plan.add("ESCALATE_TO_ANALYST", "R9: activity fits no documented pattern; hand to an analyst with the evidence")
    return plan


def initial_plan(ctx: PolicyContext, request: str | None) -> Plan:
    """Recommendation BEFORE any requested evidence comes back (3b)."""
    plan = Plan(ctx.exposure)
    v = verdict_of(ctx.p)

    if ctx.recurring_dispute:
        return (plan.add("CREATE_CASE", "R7/3a: customer disputes a charge; a case is opened for every dispute")
                .add("VERIFY_WITH_CUSTOMER", "R7: charge matches the cardholder's own recurring pattern; confirm with them")
                .add("WARN_CUSTOMER", "R7: send a recurring-charge reminder. Do not block"))

    if ctx.trigger == "customer_report":
        plan = fraud_actions(ctx, plan, "R2: customer denies the transaction")
        if ctx.conflicts and not plan.has("ESCALATE_TO_ANALYST"):
            plan.add("ESCALATE_TO_ANALYST", "R8: graph evidence conflicts with the customer's denial")
        return plan

    if ctx.pattern == "card_testing":
        plan.add("DECLINE_TRANSACTION", "R5: three or more small online authorizations within an hour, then a larger purchase")
        plan.add("STEP_UP_AUTH", "R5: require one-time passcode before further activity")
        if ctx.card_testing_big_cleared:
            plan.add("BLOCK_CARD", "R5: a purchase over $100 has already cleared")
        plan.add("CREATE_CASE", "3a: fraud probability >= 0.30")
        return plan

    if request is None and ctx.p >= 0.85:  # settled as fraud on multi-signal graph evidence
        plan = fraud_actions(ctx, plan, "R6/section 6: fraud established by independent graph evidence")
        return plan

    if request is None and ctx.p <= 0.15:
        return (plan.add("ALLOW_TRANSACTION", "Section 6: evidence settles the alert as legitimate")
                .add("CLOSE_NO_FRAUD", "Section 6: probability <= 0.15 on two or more independent pieces of evidence"))

    # Not settled: gather evidence before any block (R1 below 0.70; section 6 between 0.70 and 0.85).
    if ctx.p < 0.7:
        basis = (f"R1: probability {ctx.p:.2f} is below 0.70 and the case rests on "
                 f"{'a single signal' if ctx.n_fraud_groups <= 1 else 'signals that are not conclusive'}; verify before any block")
    else:
        basis = (f"Section 6: probability {ctx.p:.2f} is below the 0.85 stopping threshold; confirm with the cardholder before blocking")
        plan.add("DECLINE_TRANSACTION", f"Fraud likely ({ctx.p:.2f}); hold the flagged authorization while verification is pending")
    plan.add("STEP_UP_AUTH" if request == "step_up_auth" else "VERIFY_WITH_CUSTOMER", basis)
    plan.add("CREATE_CASE", "3a: a case is opened whenever evidence is requested" + (" and probability >= 0.30" if ctx.p >= 0.3 else ""))
    if ctx.connected_cards:
        plan.add("MONITOR_CONNECTED_CARDS", f"R6: {len(ctx.connected_cards)} card(s) share the {ctx.shared_origin}")
    if v == "uncertain" and (ctx.exposure > 500 or ctx.conflicts):
        plan.add("ESCALATE_TO_ANALYST", "R8: verdict uncertain and " + (f"exposure ${ctx.exposure:,.2f} exceeds $500" if ctx.exposure > 500 else "evidence conflicts"))
    elif 0.3 <= ctx.p < 0.7:
        plan.add("MONITOR_CARD", "Raise monitoring for 72 hours while verification is pending")
    return plan


def final_plan(ctx: PolicyContext, response: str | None, initial: Plan) -> Plan:
    """Recommendation AFTER the assumed response (3b). `response` is deny | confirm | no_reply | None."""
    if response is None:
        return initial
    plan = Plan(ctx.exposure)
    if response == "confirm":
        plan.add("CLOSE_NO_FRAUD", "R3: customer confirms the transaction; confirmation noted in the case file")
        if ctx.recurring_dispute:
            plan.add("WARN_CUSTOMER", "R7: recurring-charge reminder so the customer recognises future charges")
        else:
            plan.add("ALLOW_TRANSACTION", "R3: legitimate; let the transaction stand")
        return plan
    if response == "deny":
        return fraud_actions(ctx, plan, "R2: customer denies the transaction")
    # no reply within 24h
    plan.add("DECLINE_TRANSACTION", "R4: no reply within 24 hours; decline pending authorizations")
    plan.add("MONITOR_CARD", "R4: no reply within 24 hours")
    plan.add("CREATE_CASE", "3a: case stays open pending evidence")
    if ctx.exposure > 500:
        plan.add("ESCALATE_TO_ANALYST", f"R4/R8: exposure ${ctx.exposure:,.2f} exceeds $500 and the verdict remains uncertain")
    if ctx.connected_cards:
        plan.add("MONITOR_CONNECTED_CARDS", f"R6: {len(ctx.connected_cards)} card(s) share the {ctx.shared_origin}")
    return plan
