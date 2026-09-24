"""Wait until an asynchronous TigerGraph load has settled, then print vertex and edge counts.

  python -m tigra.tg_wait
"""
from __future__ import annotations

import time

from .tg_load import connect


def main(timeout_s: int = 1500) -> None:
    conn = connect()
    t0, last = time.time(), None
    while time.time() - t0 < timeout_s:
        v = conn.getVertexCount("*")
        print(f"{time.time() - t0:5.0f}s  Txn={v.get('Txn')}  ClosedCase={v.get('ClosedCase')}", flush=True)
        if v == last and v.get("Txn", 0) >= 590_742:
            break
        last = v
        time.sleep(15)
    print("vertices:", conn.getVertexCount("*"))
    print("edges:", conn.getEdgeCount("*"))


if __name__ == "__main__":
    main()
