# TIGRA: from an uncertain alert to a defensible action

*TIGRA (TigerGraph Investigative Reasoning Agent) is a fraud investigation agent built on TigerGraph.*

## What we built
We built TIGRA, an agent that investigates card-fraud alerts the way an analyst does. It starts from the trigger (a model score, a customer complaint or an analyst request) and pulls the card's behaviour and neighbourhood from the graph. It then decides what kind of fraud this is, if any, how far it goes, and what the bank should do. Every recommendation cites a rule from the bank's Fraud Policy and carries its approval route (auto, team lead or fraud manager). When the evidence is not strong enough, TIGRA asks the cardholder or requests step-up authentication, and records the recommendation both before and after the reply. The result is written back to the graph as a `FraudCase` vertex, so the next investigation can find it.

## Architecture
* **Graph layer:** TigerGraph holds customers, cards, 590k transactions, device profiles, email domains, billing regions, 5,565 closed cases, TIGRA-written cases and a document store with vector embeddings. The agent sees the graph only through a small tool catalogue, one GSQL installed query per tool. The tools are:
  * card baseline
  * card window
  * device neighbours
  * attribute-seen checks
  * recurrence
  * prior cases
  * closed-case features
  * vector search

  The same tools can be reached over REST, or through the official TigerGraph MCP server, so TIGRA calls the graph the way an LLM tool call would.
* **Detectors** turn tool results into evidence. Each piece of evidence has a claim, the query it came from, the dataset IDs it rests on, a log-odds weight and an independence group.
* **Evidence fusion** starts from a trigger-specific prior. The risk score only shifts the prior; it is never a verdict. The fusion also tracks how many independent evidence groups support the current direction, which is exactly what the policy's stopping rule asks for.
* **The policy engine** encodes R1–R10, the approval routing and the "case vs. report" test. The LLM cannot pick actions.
* **GraphRAG** retrieves policy rules, typologies, regulatory guidance and closed-case narratives through vector search. It then combines them with the graph evidence and the similar cases, and that combined context (not raw rows) is what the LLM sees when it writes summaries and SAR narratives.
* **The UI** streams every tool call, piece of evidence and probability change live, and lets a team lead or fraud manager approve the L1/L2 actions.

## How TigerGraph is used
The decisive evidence in several cases is only visible across cards. HHG-019's card looks normal on its own: it has bought ~$100 of product R before. Traversing DeviceProfile ← Transaction → Card shows the same rare device profile placing identical ~$100 purchases for five unrelated customers in five days, with the same purchaser and recipient email pair. HHG-014 shows the same thing at a larger scale: an SM-G935F profile behind an anonymous proxy, used on 28 cards in November and linked to four closed "undocumented" cases. These multi-hop, time-windowed neighbourhood queries are what a graph is for. The case-memory edges (`CASE_ON_CARD`, `CASE_DEVICE`, `CASE_CONNECTED`) make each new case evidence for the next one.

## Agentic capabilities
* **Hypothesis-driven tool selection:** device tools for online alerts, region tools for card-present alerts, and early stopping once the probability is settled.
* **Uncertainty handling:** R1 verification below 0.70, a DECLINE_TRANSACTION hold between 0.70 and 0.85, and three simulated replies (deny, confirm, no reply). The no-reply case keeps genuinely ambiguous alerts open under R4/R8 instead of forcing a verdict.
* **Memory:** retrieval combines behavioural similarity with graph proximity. We found a base-rate trap in the history: every cleared case was a model alert and every customer report was confirmed fraud. Similarity-weighted outcomes would therefore mostly have learned the trigger type, so memory only moves the probability through shared-device links.
* **Explanations:** a stop reason for every case, a `what_changed` note between the initial and final actions, and SARs that answer who, what, when, where, how and why.

## What we learned
* The labels hide the schema: card IDs had to be reverse-engineered, and the result checked against all 14,975 labelled rows.
* "Suspicious" is usually a property of the neighbourhood, not the transaction.
* The hardest part of next-best-action is saying "not yet", and a policy engine separate from the LLM makes that auditable.

## What we would improve with more time
* Calibrate the evidence weights with proper likelihood-ratio estimation on held-out cases.
* Add region-cluster and recipient-email rings, alongside the device rings we detect today.
* Stream new alerts from the exam period for autonomous monitoring.
* Use real customer-contact integrations instead of simulated replies.
