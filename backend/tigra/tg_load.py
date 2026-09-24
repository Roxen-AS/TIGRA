"""Load TigraGraph into TigerGraph (Savanna or Community Edition).

  python -m tigra.tg_load --export     # write load CSVs to data/tg/ from the DuckDB store (no TigerGraph needed)
  python -m tigra.tg_load --all        # schema + loading job + data + queries + GraphRAG doc vectors (needs TG_HOST, TG_SECRET)

Steps can also be run individually: --schema --load --queries --docs.
"""
from __future__ import annotations

import argparse
import time

import duckdb

from . import config
from .kb import KnowledgeBase, embed

TG_DIR = config.DATA_DIR / "tg"
FILES = {
    "f_cards": "cards.csv", "f_devices": "devices.csv", "f_txns": "txns.csv", "f_next": "next.csv",
    "f_cases": "closed_cases.csv", "f_case_txn": "case_txn.csv", "f_case_conn": "case_conn.csv",
}


def export() -> None:
    TG_DIR.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(config.DB_PATH), read_only=True)
    s = lambda col: f"coalesce(CAST({col} AS VARCHAR), '')"
    g = lambda col: f"coalesce(regexp_replace(CAST({col} AS VARCHAR), '\\.0$', ''), '')"
    jobs = {
        "cards.csv": "SELECT card_id AS id, customer_id, coalesce(network,'') AS network, coalesce(card_type,'') AS card_type FROM card",
        "devices.csv": f"SELECT device_id AS id, profile, {s('device_info')} device_info, {s('os')} os, {s('browser')} browser, {s('screen')} screen FROM device",
        "txns.csv": f"""SELECT txn_id AS id, strftime(ts, '%Y-%m-%d %H:%M:%S') ts, amt, product, channel, card_id, customer_id,
                        {g('addr1')} addr1, {g('addr2')} addr2, {g('dist1')} dist1, {s('p_email')} p_email, {s('r_email')} r_email,
                        risk_score, {s('device_id')} device_id, {s('device_status')} device_status, {s('proxy')} proxy,
                        {s('device_type')} device_type, {s('M1')} M1, {s('M2')} M2, {s('M3')} M3, {s('M4')} M4, {s('M5')} M5, {s('M6')} M6,
                        coalesce(C1, 0) C1, coalesce(C13, 0) C13, {g('D1')} D1, {g('D15')} D15 FROM txn""",
        "next.csv": """SELECT txn_id AS from_txn, nxt AS to_txn FROM (
                         SELECT txn_id, lead(txn_id) OVER (PARTITION BY card_id ORDER BY ts, txn_id) nxt FROM txn) WHERE nxt IS NOT NULL""",
        "closed_cases.csv": """SELECT case_id AS id, customer_id, card_id, opened_at, closed_at, outcome, pattern, exposure_usd, n_txns,
                               report_filed, actions_taken, analyst_notes FROM closed_case""",
        "case_txn.csv": "SELECT case_id, txn_id FROM closed_case_txn",
        "case_conn.csv": "SELECT case_id, card_id FROM closed_case_conn",
    }
    for name, sql in jobs.items():
        con.execute(f"COPY ({sql}) TO '{(TG_DIR / name).as_posix()}' (HEADER, DELIMITER ',', QUOTE '\"')")
        print(f"  exported {name}")
    con.close()


def connect():
    from pyTigerGraph import TigerGraphConnection
    conn = TigerGraphConnection(host=config.TG_HOST, graphname=config.TG_GRAPH, username=config.TG_USERNAME,
                                password=config.TG_PASSWORD, gsqlSecret=config.TG_SECRET, tgCloud="tgcloud" in config.TG_HOST)
    if config.TG_SECRET:
        conn.getToken(config.TG_SECRET)
    return conn


def gsql_file(conn, name: str) -> None:
    text = (config.ROOT / "tigergraph" / name).read_text(encoding="utf-8")
    print(conn.gsql(text))


def load(conn) -> None:
    for tag, fname in FILES.items():
        t0 = time.time()
        res = conn.runLoadingJobWithFile(str(TG_DIR / fname), tag, "load_tigra", sizeLimit=2_000_000_000, timeout=0)
        print(f"  {fname}: {res and res[0].get('statistics', {}).get('validLine')} lines in {time.time() - t0:.0f}s")


def docs(conn) -> None:
    con = duckdb.connect(str(config.DB_PATH), read_only=True)
    cur = con.execute("SELECT case_id, outcome, pattern, analyst_notes FROM closed_case")
    notes = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    kb = KnowledgeBase(notes)
    rows = [(d.doc_id, {"title": d.title, "text": d.text, "source": d.source}) for d in kb.docs]
    print(f"  upserting {conn.upsertVertices('Doc', rows)} Doc vertices")
    for d in kb.docs:  # vector attribute is written separately from scalar attributes
        conn.upsertVertex("Doc", d.doc_id, {"embedding": [round(float(x), 6) for x in embed(d.title + ' ' + d.text)]})


def main() -> None:
    ap = argparse.ArgumentParser()
    for flag in ("export", "schema", "load", "queries", "docs", "all"):
        ap.add_argument(f"--{flag}", action="store_true")
    a = ap.parse_args()
    if a.export or a.all:
        export()
    if not (a.schema or a.load or a.queries or a.docs or a.all):
        return
    if not config.TG_HOST:
        raise SystemExit("Set TG_HOST / TG_SECRET (or TG_USERNAME / TG_PASSWORD) in backend/.env first.")
    conn = connect()
    if a.schema or a.all:
        gsql_file(conn, "schema.gsql")
        gsql_file(conn, "loading_job.gsql")
    if a.load or a.all:
        load(conn)
    if a.queries or a.all:
        gsql_file(conn, "queries.gsql")
    if a.docs or a.all:
        docs(conn)


if __name__ == "__main__":
    main()
