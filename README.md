# TIGRA: TigerGraph Investigative Reasoning Agent

Agentic fraud investigation on TigerGraph for the HHGOA_IEEE dataset.

TIGRA is an AI agent that takes a fraud alert, investigates it across the transaction graph, works out whether and how fraud happened, how far it goes, and what to do next under the bank's Fraud Policy v1.0. It asks for more evidence when the policy requires it and records how the recommendation changed. Every case is written back to the graph as memory for the next investigation.

Output for the 20 benchmark cases: [`cases/`](cases/) (one answer file per case; all pass `python -m tigra.validate`).

## What it does

```
alert ─▶ trigger prior ─▶ graph tools (card baseline, window, device ring, region, recurrence)
      ─▶ detectors → log-odds evidence fusion ─▶ §6 stopping rule?
      ─▶ no: request evidence (R1) → simulated reply → update
      ─▶ policy engine (R1–R10, routes auto/L1/L2) ─▶ case + SAR + next best actions
      ─▶ write FraudCase vertex (memory) ─▶ UI / answer file
```

| Challenge requirement | Where |
|---|---|
| Trigger by score, customer report, analyst | `agent.py` priors per trigger; ad-hoc investigation of any transaction in the UI |
| Evidence from graph, device/identity, behaviour, prior cases, documents | `tools.py` catalogue → `store_local.py` / `store_tg.py` (GSQL in `tigergraph/queries.gsql`) |
| Pattern identification incl. undocumented | `detectors.py`: card testing, structuring under $500, device-sharing rings, mixed-channel ATO, out-of-region vs trip, CNP bursts, recurring charges |
| Uncertainty and when to stop | calibrated log-odds posterior; §6 rule (≥0.85 / ≤0.15 with ≥2 independent evidence groups) |
| Controlled evidence gathering | `VERIFY_WITH_CUSTOMER` / `STEP_UP_AUTH`, simulated reply (deny / confirm / no reply) derived from the posterior and recorded |
| Policies, permissions, approvals | `policy.py` (every action cites a rule; routes per §2); API refuses L1/L2 approval from the wrong role |
| Case memory | `memory.py`: feature-vector + graph-proximity retrieval over 5,565 closed cases + cases TIGRA wrote |
| GraphRAG | `kb.py`: policy, typologies, regulatory guidance, case narratives; embeddings stored in the TigerGraph `Doc.embedding` vector attribute |
| TigerGraph MCP | `GRAPH_BACKEND=mcp` routes every graph call through the official `tigergraph-mcp` server; `tigra/mcp_server.py` exposes the investigation tools to any MCP client |
| UI | `frontend/`: alert queue, live investigation trace (SSE), probability trace, actions + approvals, SAR, graph view |

## Key data findings

* **Card IDs** are not a column. They are `customer_id-K<n>`, where n ranks the `(card4, card6)` pairs within the customer, nulls first. This was checked against all 14,975 labelled rows.
* Device profile = `DeviceInfo | id_30 | id_31 | id_33`, which gives 9,706 profiles. The all-unknown profile and profiles used by more than 150 cards are treated as non-identifying.
* **Base-rate trap in memory:** every cleared closed case came from a model alert, and every customer report was confirmed. So "similar cases were cleared" mostly encodes the trigger type. The agent only lets memory move the probability through graph-linked evidence, namely shared devices with confirmed fraud.
* Undocumented patterns found:
  * the SM-G935F anonymous-proxy device ring (HHG-014, 28 cards);
  * a Windows/chrome 61 ring with identical ~$100 purchases and the same email pair across 5 customers (HHG-019);
  * an SM-G610F ring across 4 cards (HHG-011);
  * structuring just under $500 (HHG-006).

## Run it

```bash
cd backend
pip install -r requirements.txt
python -m tigra.etl --src "<path>/HHGOA_IEEE"      # ~2 min: CSV → Parquet → data/fraud.duckdb
python -m tigra.run_cases --fresh                   # 20 answer files in ~10 s → cases/
python -m tigra.validate                            # answer-format + policy checks
python -m unittest discover -s tests              # policy + detector unit tests
uvicorn tigra.api:app --port 8000                   # UI at http://localhost:8000  (deep link: /#HHG-014)
```

### With TigerGraph (Savanna or Community Edition)

```bash
cp .env.example .env        # set TG_HOST, TG_SECRET (or username/password), GRAPH_BACKEND=tigergraph
python -m tigra.tg_load --all # schema, loading job, 590k txns + edges, installed queries, Doc vectors
python -m tigra.run_cases --fresh
GRAPH_BACKEND=mcp ...       # same queries through the official TigerGraph MCP server
```

Schema: `Customer, Card, Txn, DeviceProfile, EmailDomain, BillingRegion, ClosedCase, FraudCase, Doc(+embedding)`. Edges: `OWNS, MADE, FROM_DEVICE, PURCHASER_EMAIL, RECIPIENT_EMAIL, BILLED_IN, NEXT, INVOLVES, ON_CARD, CONNECTED_TO` and the case-memory edges `CASE_*` / `SIMILAR_TO`. Details are in `tigergraph/`.

The local DuckDB mirror implements the same tool interface with the same result shapes. It exists so TIGRA, the tests and the demo run offline. The GSQL files and the TigerGraph and MCP transports are written against the pyTigerGraph 2.0 and tigergraph-mcp 1.0.3 APIs.

### Optional LLM

Set `ANTHROPIC_API_KEY` to have Claude write the analyst summary, the SAR narrative and the undocumented-pattern descriptions. It works from GraphRAG context (evidence claims, retrieved policy passages and similar cases) and reports the tokens it used. The LLM never chooses actions. Without a key, deterministic templates are used and `tokens` is 0.

## Layout

```
backend/tigra/   etl · store_local · store_tg · tg_load · tools · detectors · policy · memory · kb · llm · agent · api · mcp_server · run_cases · validate
backend/tests/ unit tests
tigergraph/    schema.gsql · loading_job.gsql · queries.gsql
frontend/      index.html · app.js · style.css (no build step)
docs/kb/       GraphRAG corpus (policy, patterns, regulatory summaries)
docs/blog.md   technical write-up
cases/         20 answer files + replayable traces
```
