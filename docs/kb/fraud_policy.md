# Fraud Policy

Version 1.0. This is the policy your agent operates under. Action names and approval routes in your case files must use the exact identifiers below.

### 0. What the agent starts with

Every transaction carries a `risk_score` between 0 and 1 from the bank's detection model. The model is useful and imperfect: many high scores are legitimate, and some fraud scores low. A score is a reason to look, never a verdict. The only confirmed outcomes are in the closed cases.

### 1. Actions

| Action | What it does | Customer impact |
|---|---|---|
| `ALLOW_TRANSACTION` | Let the flagged transaction stand | None |
| `DECLINE_TRANSACTION` | Decline the flagged authorization only. Card stays active | Low |
| `MONITOR_CARD` | Card stays active; raise monitoring sensitivity for 72 hours | None |
| `MONITOR_CONNECTED_CARDS` | Put other cards linked to the same device profile, region cluster, or ring under monitoring | None |
| `WARN_CUSTOMER` | Send an informational message (e.g. a recurring charge reminder, a security tip) | None |
| `VERIFY_WITH_CUSTOMER` | Ask the cardholder whether they made the transaction. Card stays active pending reply | Low |
| `STEP_UP_AUTH` | Require a one-time passcode or app confirmation before further activity | Low |
| `BLOCK_CARD` | Block this card and reissue | High |
| `BLOCK_ALL_CARDS` | Block every card the customer holds | Very high |
| `GENERATE_REPORT` | Write up the investigation for the internal record, without opening a case | None |
| `CREATE_CASE` | Open an internal fraud case with the evidence attached, and write it to the graph. See 3a | None |
| `FILE_REPORT` | File a suspicious activity report with the regulator. See 3a | None |
| `ESCALATE_TO_ANALYST` | Hand the case to a human analyst with the evidence | None |
| `CLOSE_NO_FRAUD` | Close the alert as legitimate | None |

An agent may recommend several actions for one case. Order them by what happens first.

### 2. Approval routing

| Route | Applies to |
|---|---|
| `auto` | `ALLOW_TRANSACTION`, `MONITOR_CARD`, `MONITOR_CONNECTED_CARDS`, `WARN_CUSTOMER`, `VERIFY_WITH_CUSTOMER`, `STEP_UP_AUTH`, `GENERATE_REPORT`, `CREATE_CASE`, `ESCALATE_TO_ANALYST`, `CLOSE_NO_FRAUD` |
| `L1` (team lead) | `DECLINE_TRANSACTION`; `BLOCK_CARD` when exposure ≤ $2,500 |
| `L2` (fraud manager) | `BLOCK_CARD` when exposure > $2,500; `BLOCK_ALL_CARDS` always; `FILE_REPORT` always |

The agent recommends. Only `auto` actions may be executed by the agent. `L1` and `L2` actions are recommended with the route stated and wait for a human.

### 3. Rules

**R1. Verify before you block on a weak signal.** If the case rests on a single signal (including a risk score alone) and your assessed fraud probability is below 0.70, recommend `VERIFY_WITH_CUSTOMER` or `STEP_UP_AUTH` before any block. Blocking a legitimate customer on one signal is a policy breach.

**R2. Customer denies the transaction.** Recommend `BLOCK_CARD` and `CREATE_CASE`. Add `FILE_REPORT` if exposure exceeds $1,000 or the case connects to a shared device profile or another card's fraud.

**R3. Customer confirms the transaction.** Recommend `CLOSE_NO_FRAUD`. Note the confirmation in the case file.

**R4. No reply within 24 hours.** Recommend `MONITOR_CARD` and `DECLINE_TRANSACTION` for pending authorizations. Escalate if exposure exceeds $500.

**R5. Card testing.** Three or more small online authorizations on one card within an hour, followed by a larger purchase: recommend `DECLINE_TRANSACTION` and `STEP_UP_AUTH`. If a purchase over $100 has already cleared, recommend `BLOCK_CARD`.

**R6. Shared origin.** When several cards show fraud from the same device profile, the same billing region, or the same recipient email in one window, name the shared element, recommend `CREATE_CASE` and `FILE_REPORT`, and `MONITOR_CONNECTED_CARDS` for every card that shares it.

**R7. Disputed but legitimate.** When the customer disputes a charge that matches their own recurring pattern (same merchant, same amount, monthly), recommend `CREATE_CASE`, `VERIFY_WITH_CUSTOMER`, and `WARN_CUSTOMER`. Do not block.

**R8. Escalate when uncertain and exposed.** If the verdict is `uncertain` and exposure exceeds $500, or the evidence conflicts, recommend `ESCALATE_TO_ANALYST`.

**R9. Undocumented patterns.** When activity fits none of the known patterns but the evidence shows coordinated or repeated abuse across customers, recommend `CREATE_CASE`, `FILE_REPORT`, and `ESCALATE_TO_ANALYST`, and describe the pattern in your own words. Do not force it into a known category.

**R10. Never `BLOCK_ALL_CARDS`** unless at least two of the customer's cards show confirmed fraud or the customer's credentials are confirmed compromised.

### 3a. A case is not a report

Two different things, and the agent produces both.

**A case** (`CREATE_CASE`) is the bank's internal record of an investigation. Open one whenever fraud probability reaches 0.30, whenever you request evidence, or whenever a customer disputes a charge. A case can be closed as fraud or as legitimate. It can be updated when new evidence arrives. It should be written into the graph so later investigations can find it: a case that names a merchant or a device becomes evidence for the next analyst.

**A suspicious activity report** (`FILE_REPORT`) is a regulatory filing sent outside the bank. File one when fraud is confirmed or strongly suspected **and** at least one of these holds: exposure exceeds $1,000; the activity connects to a shared device profile, a shared region cluster, or another customer's fraud; the pattern is coordinated or undocumented (rule R9). A report always has a case behind it. Most cases never need a report. The report narrative must stand on its own: who, what, when, where, how, and why it is suspicious.

Deciding correctly between "case only" and "case plus report" is part of the next-best-action score.

### 3b. The next best action can change

Recommend what the evidence supports now, then request more evidence if the policy calls for it, then recommend again. Example: probability 0.45 on a single signal, so the initial action is `VERIFY_WITH_CUSTOMER` under R1. The customer denies the transaction. Probability rises, and the final actions become `BLOCK_CARD`, `CREATE_CASE`, and possibly `FILE_REPORT` under R2, with connected cards placed under monitoring. Record both the initial and the final recommendation and what changed between them.

### 4. Exposure

Exposure is the sum of the absolute amounts of every transaction the agent has identified as part of the fraud episode, including the flagged one. Report it in USD.

### 5. Gathering more evidence

The agent may, without approval, ask the customer to validate a transaction, request step-up authentication, or request information from an analyst. In this round those responses are not provided. Simulate them in your own system and state the assumption you made in the case file's `evidence_requests`.

### 6. Stopping

Stop investigating when one of these holds:

- Fraud probability is at or above 0.85, or at or below 0.15, supported by at least two independent pieces of evidence
- A verification response settles the question
- Further steps are unlikely to change the decision. Say so in `stop_reason`

Investigations that continue past a defensible decision waste time. Investigations that stop before one create risk. Both are marked down.

### 7. Explaining

Every recommendation must state what evidence was used, why more evidence was requested if it was, and why the chosen actions follow from this policy. Cite the rule number.

---

