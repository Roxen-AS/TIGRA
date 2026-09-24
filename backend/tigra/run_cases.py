"""Run the agent on every case in the case pack and write cases/<case_id>.json.

Usage:  python -m tigra.run_cases [--only HHG-001 HHG-002] [--fresh]
Cases run in case-pack chronological order so case memory written by earlier investigations is available to later ones.
"""
from __future__ import annotations

import argparse

from .config import CASES_DIR
from .runtime import runtime, save_case


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--fresh", action="store_true", help="clear agent-written cases from the graph first")
    args = ap.parse_args()
    store, _, _, agent = runtime()
    if args.fresh:
        store.reset_agent_cases()
    CASES_DIR.mkdir(exist_ok=True)
    alerts = sorted(store.list_alerts(), key=lambda a: a["opened_at"])
    for a in alerts:
        if args.only and a["case_id"] not in args.only:
            continue
        trace: list[dict] = []
        ans = agent.investigate(alert=a, emit=trace.append)
        save_case(ans, trace)
        c = ans["case"]
        print(f"{a['case_id']} {a['trigger_type'][:8]:8s} p={c['fraud_probability']:.2f} {c['verdict']:10s} {c['pattern']:28s} "
              f"${c['exposure_usd']:>9,.2f} n={len(c['affected_txn_ids']):<3d} sar={str(ans['sar']['file'])[0]} "
              f"req={','.join(r['type'][:8] for r in ans['evidence_requests']) or '-':9s} "
              f"final={','.join(x['action'] for x in ans['next_best_actions']['final'])}")


if __name__ == "__main__":
    main()
