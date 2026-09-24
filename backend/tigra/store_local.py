"""Embedded graph store: the same traversal tools as the TigerGraph installed queries, served from DuckDB.

Every public method mirrors one GSQL query in tigergraph/queries/*.gsql (same name, same parameters, same
JSON shape), so the agent is backend-agnostic. The DuckDB mirror exists so the agent runs offline and in CI;
TigerGraph remains the system of record when TG_HOST is configured.
"""
from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any

import duckdb

from .config import DATA_DIR, DB_PATH

MEM_PATH = DATA_DIR / "memory.duckdb"
AGENT_CASE_DDL = """CREATE TABLE IF NOT EXISTS agent_case (graph_case_id VARCHAR PRIMARY KEY, case_id VARCHAR, card_id VARCHAR,
    customer_id VARCHAR, opened_at VARCHAR, status VARCHAR, verdict VARCHAR, pattern VARCHAR, fraud_probability DOUBLE,
    exposure_usd DOUBLE, summary VARCHAR, sar_filed BOOLEAN, txn_ids VARCHAR, connected_card_ids VARCHAR,
    device_ids VARCHAR, actions VARCHAR, updated_at VARCHAR, vec VARCHAR)"""

TXN_COLS = ("txn_id, ts, amt, product, channel, card_id, customer_id, addr1, addr2, dist1, p_email, r_email, "
            "risk_score, device_id, device_status, proxy, device_type, M1, M2, M3, M4, M5, M6, C1, C13, D1, D15")


def _jsonable(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, float):
        return None if v != v else round(v, 4)  # NaN -> None
    return v


def _rows(cur: duckdb.DuckDBPyConnection) -> list[dict]:
    cols = [d[0] for d in cur.description]
    return [{c: _jsonable(v) for c, v in zip(cols, row)} for row in cur.fetchall()]


def _ts(s: str | datetime) -> datetime:
    return s if isinstance(s, datetime) else datetime.fromisoformat(str(s))


class LocalGraphStore:
    backend = "local-duckdb"

    def __init__(self, path=DB_PATH):
        if not path.exists():
            raise FileNotFoundError(f"{path} missing. Build it first: cd backend && python -m tigra.etl --src <HHGOA_IEEE>")
        # The dataset is read-only, so the API, MCP server and batch runner can all open it at once.
        self._con = duckdb.connect(str(path), read_only=True)
        self._lock = threading.Lock()
        with self._mem() as m:
            m.execute(AGENT_CASE_DDL)

    @contextmanager
    def _mem(self):
        """Case memory lives in its own small file, opened only for the duration of one read/write.
        DuckDB allows one writer per file, so retry briefly if another process is mid-write."""
        for attempt in range(40):
            try:
                con = duckdb.connect(str(MEM_PATH))
                break
            except duckdb.IOException:
                if attempt == 39:
                    raise
                time.sleep(0.05 * (attempt + 1))
        try:
            with self._lock:
                yield con
        finally:
            con.close()

    def _mq(self, sql: str, params: list | None = None) -> list[dict]:
        with self._mem() as m:
            return _rows(m.execute(sql, params or []))

    def _q(self, sql: str, params: list | None = None) -> list[dict]:
        cur = self._con.cursor()
        try:
            return _rows(cur.execute(sql, params or []))
        finally:
            cur.close()

    # ------------------------------------------------------------------ lookups
    def list_alerts(self) -> list[dict]:
        return self._q("SELECT * FROM case_pack ORDER BY case_id")

    def get_alert(self, case_id: str) -> dict | None:
        r = self._q("SELECT * FROM case_pack WHERE case_id = ?", [case_id])
        return r[0] if r else None

    def get_transaction(self, txn_id: int) -> dict | None:
        r = self._q(f"""SELECT {TXN_COLS}, d.profile AS device_profile, d.os, d.browser, d.device_info
                        FROM txn LEFT JOIN device d USING (device_id) WHERE txn_id = ?""", [int(txn_id)])
        return r[0] if r else None

    def customer_cards(self, customer_id: str) -> list[dict]:
        return self._q("""SELECT card_id, any_value(card4) AS network, any_value(card6) AS card_type, count(*) AS n_txn,
                                 min(ts) AS first_ts, max(ts) AS last_ts
                          FROM txn WHERE customer_id = ? GROUP BY card_id ORDER BY card_id""", [customer_id])

    # ------------------------------------------------------------------ card behaviour
    def card_profile(self, card_id: str, before_ts: str) -> dict:
        """Behavioural baseline of a card strictly before `before_ts` (no look-ahead into the alert)."""
        base = self._q("""SELECT count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts,
                                 median(amt) AS amt_median, quantile_cont(amt, 0.25) AS amt_p25,
                                 quantile_cont(amt, 0.75) AS amt_p75, quantile_cont(amt, 0.95) AS amt_p95,
                                 max(amt) AS amt_max, avg((channel = 'online')::INT) AS online_share,
                                 count(DISTINCT device_id) AS n_devices, count(DISTINCT addr1) AS n_regions
                          FROM txn WHERE card_id = ? AND ts < ?""", [card_id, before_ts])[0]
        base["products"] = self._q("""SELECT product, count(*) AS n, median(amt) AS amt_median, max(amt) AS amt_max
                                      FROM txn WHERE card_id = ? AND ts < ? GROUP BY 1 ORDER BY 2 DESC""",
                                   [card_id, before_ts])
        base["regions"] = self._q("""SELECT addr1 AS region, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts,
                                            count(DISTINCT ts::DATE) AS days
                                     FROM txn WHERE card_id = ? AND ts < ? AND addr1 IS NOT NULL
                                     GROUP BY 1 ORDER BY 2 DESC LIMIT 12""", [card_id, before_ts])
        base["emails"] = self._q("""SELECT p_email AS email, count(*) AS n FROM txn
                                    WHERE card_id = ? AND ts < ? AND p_email IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 8""",
                                 [card_id, before_ts])
        return base

    def card_window(self, card_id: str, start_ts: str, end_ts: str, limit: int = 400) -> list[dict]:
        return self._q(f"""SELECT {TXN_COLS} FROM txn WHERE card_id = ? AND ts BETWEEN ? AND ?
                           ORDER BY ts LIMIT ?""", [card_id, start_ts, end_ts, limit])

    def region_history(self, card_id: str, region: float, before_ts: str) -> dict:
        return self._q("""SELECT count(*) AS n, min(ts) AS first_ts, count(DISTINCT ts::DATE) AS days FROM txn
                          WHERE card_id = ? AND addr1 = ? AND ts < ?""", [card_id, region, before_ts])[0]

    def device_seen_on_card(self, card_id: str, device_id: str, before_ts: str) -> dict:
        return self._q("""SELECT count(*) AS n, min(ts) AS first_ts FROM txn
                          WHERE card_id = ? AND device_id = ? AND ts < ?""", [card_id, device_id, before_ts])[0]

    def email_seen_on_card(self, card_id: str, email: str, before_ts: str) -> dict:
        return self._q("""SELECT count(*) AS n, min(ts) AS first_ts FROM txn
                          WHERE card_id = ? AND p_email = ? AND ts < ?""", [card_id, email, before_ts])[0]

    def amount_recurrence(self, card_id: str, txn_id: int, amt: float, product: str, region: float | None,
                          tol: float = 0.02) -> dict:
        """Earlier charges on this card with the same product (and region for card-present) at ~the same amount."""
        band = max(tol * amt, 0.5)
        region_sql = "AND addr1 IS NOT DISTINCT FROM ?" if product == "W" else ""
        params: list = [card_id, product, int(txn_id), amt - band, amt + band]
        if product == "W":
            params.append(region)
        hits = self._q(f"""SELECT txn_id, ts, amt, addr1, p_email, device_id FROM txn
                           WHERE card_id = ? AND product = ? AND txn_id < ? AND amt BETWEEN ? AND ? {region_sql}
                           ORDER BY ts""", params)
        scope = self._q(f"""SELECT count(*) AS n FROM txn WHERE card_id = ? AND product = ? AND txn_id < ? {region_sql}""",
                        [card_id, product, int(txn_id)] + ([region] if product == "W" else []))[0]["n"]
        return {"hits": hits, "scope_n": scope}

    # ------------------------------------------------------------------ graph neighbourhoods
    def device_neighbors(self, device_id: str, center_ts: str, days: int = 14) -> dict:
        """Device -> transactions -> cards: who else used this device profile around the alert."""
        c = _ts(center_ts)
        lo, hi = str(c - timedelta(days=days)), str(c + timedelta(days=days))
        life = self._q("""SELECT d.profile, count(*) AS n_txn, count(DISTINCT t.card_id) AS n_cards,
                                 min(t.ts) AS first_ts, max(t.ts) AS last_ts
                          FROM txn t JOIN device d USING (device_id) WHERE device_id = ? GROUP BY 1""", [device_id])
        window = self._q(f"""SELECT {TXN_COLS} FROM txn WHERE device_id = ? AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 600""",
                         [device_id, lo, hi])
        cases = self._q("""SELECT DISTINCT cc.case_id, cc.card_id, cc.outcome, cc.pattern, cc.opened_at
                           FROM closed_case_txn x JOIN txn t USING (txn_id) JOIN closed_case cc USING (case_id)
                           WHERE t.device_id = ? ORDER BY cc.opened_at""", [device_id])
        return {"device": life[0] if life else {"profile": None, "n_txn": 0, "n_cards": 0},
                "window_days": days, "window_txns": window, "closed_cases": cases}

    # ------------------------------------------------------------------ case memory
    def prior_cases(self, customer_id: str, before_ts: str) -> list[dict]:
        closed = self._q("""SELECT case_id, card_id, outcome, pattern, opened_at, closed_at, exposure_usd, n_txns,
                                   report_filed, analyst_notes, 'closed_case' AS source
                            FROM closed_case WHERE customer_id = ? AND opened_at < ? ORDER BY opened_at""",
                         [customer_id, before_ts])
        agent = self._mq("""SELECT graph_case_id AS case_id, card_id, verdict AS outcome, pattern, opened_at, NULL AS closed_at,
                                  exposure_usd, NULL AS n_txns, sar_filed AS report_filed, summary AS analyst_notes,
                                  'agent_case' AS source
                           FROM agent_case WHERE customer_id = ? AND opened_at < ? ORDER BY opened_at""",
                        [customer_id, before_ts])
        return closed + agent

    def closed_case_features(self) -> list[dict]:
        """One row per closed case with the behavioural features used by the memory index."""
        return self._q("""
            SELECT cc.case_id, cc.card_id, cc.customer_id, cc.outcome, cc.pattern, cc.opened_at,
                   CAST(cc.exposure_usd AS DOUBLE) AS exposure_usd, CAST(cc.n_txns AS INT) AS n_txns,
                   cc.connected_card_ids, cc.analyst_notes, cc.report_filed,
                   avg((t.channel = 'online')::INT) AS online_share,
                   avg((t.device_status = 'New')::INT) AS new_device_share,
                   avg((t.proxy IS NOT NULL)::INT) AS proxy_share,
                   min(t.amt) AS amt_min, max(t.amt) AS amt_max,
                   date_diff('minute', min(t.ts), max(t.ts)) AS span_min,
                   mode(t.product) AS product, max(t.risk_score) AS risk_max,
                   list(DISTINCT t.device_id) FILTER (WHERE t.device_id IS NOT NULL) AS device_ids
            FROM closed_case cc JOIN closed_case_txn x USING (case_id) JOIN txn t USING (txn_id)
            GROUP BY ALL""")

    def agent_cases(self) -> list[dict]:
        return self._mq("SELECT * FROM agent_case ORDER BY updated_at")

    def write_case(self, rec: dict) -> str:
        """Upsert the FraudCase vertex (+ its edges, encoded as id lists) so later investigations retrieve it."""
        cols = ["graph_case_id", "case_id", "card_id", "customer_id", "opened_at", "status", "verdict", "pattern",
                "fraud_probability", "exposure_usd", "summary", "sar_filed", "txn_ids", "connected_card_ids",
                "device_ids", "actions", "updated_at", "vec"]
        vals = [json.dumps(rec[c]) if isinstance(rec.get(c), (list, dict)) else rec.get(c) for c in cols]
        with self._mem() as m:
            m.execute(f"INSERT OR REPLACE INTO agent_case ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals)
        return rec["graph_case_id"]

    def reset_agent_cases(self) -> None:
        with self._mem() as m:
            m.execute("DELETE FROM agent_case")

    def stats(self) -> dict:
        s = self._q("""SELECT (SELECT count(*) FROM txn) AS transactions, (SELECT count(*) FROM card) AS cards,
                              (SELECT count(*) FROM customer) AS customers, (SELECT count(*) FROM device) AS devices,
                              (SELECT count(*) FROM closed_case) AS closed_cases""")[0]
        s["agent_cases"] = self._mq("SELECT count(*) AS n FROM agent_case")[0]["n"]
        return s
