"""One-time ETL: raw HHGOA_IEEE CSVs -> compact DuckDB analytical store + TigerGraph load files.

Usage:  python -m tigra.etl --src "<path to HHGOA_IEEE folder>"

Derivations (verified against every labelled row in closed_cases_history.csv + case_pack.csv, 14,975/14,975):
  card_id   = customer_id || '-K' || rank of (card4, card6) within the customer, NULLs first
  device_id = 'D' || zero-padded rank of the profile string "DeviceInfo | OS | browser | screen"
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

import duckdb

from .config import DATA_DIR, DB_PATH

C_COLS = ", ".join(f"C{i}" for i in range(1, 15))
D_COLS = ", ".join(f"D{i}" for i in range(1, 16))
M_COLS = ", ".join(f"M{i}" for i in range(1, 10))


def build(src: Path) -> None:
    t0 = time.time()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tx_src = DATA_DIR / "transactions.parquet"
    id_src = DATA_DIR / "identity.parquet"
    con = duckdb.connect()
    # Parquet mirrors of the raw CSVs keep every original column (V1..V339 are read on demand).
    if not tx_src.exists():
        con.execute(f"COPY (SELECT * FROM read_csv_auto('{(src / 'transactions.csv').as_posix()}', sample_size=-1)) "
                    f"TO '{tx_src.as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
    if not id_src.exists():
        con.execute(f"COPY (SELECT * FROM read_csv_auto('{(src / 'identity.csv').as_posix()}', sample_size=-1)) "
                    f"TO '{id_src.as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
    con.close()

    if DB_PATH.exists():
        DB_PATH.unlink()
    con = duckdb.connect(str(DB_PATH))
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"CREATE VIEW raw_t AS SELECT * FROM '{tx_src.as_posix()}'")
    con.execute(f"CREATE VIEW raw_i AS SELECT * FROM '{id_src.as_posix()}'")

    con.execute("""
        CREATE TABLE card AS
        SELECT customer_id, card4 AS network, card6 AS card_type,
               customer_id || '-K' || row_number() OVER (PARTITION BY customer_id
                   ORDER BY card4 NULLS FIRST, card6 NULLS FIRST) AS card_id
        FROM (SELECT DISTINCT customer_id, card4, card6 FROM raw_t)
    """)
    con.execute("""
        CREATE TABLE device AS
        SELECT 'D' || lpad(CAST(row_number() OVER (ORDER BY profile) AS VARCHAR), 6, '0') AS device_id, *
        FROM (SELECT DISTINCT
                coalesce(DeviceInfo,'?') || ' | ' || coalesce(id_30,'?') || ' | ' || coalesce(id_31,'?') || ' | ' || coalesce(id_33,'?') AS profile,
                DeviceInfo AS device_info, id_30 AS os, id_31 AS browser, id_33 AS screen
              FROM raw_i)
    """)
    con.execute(f"""
        CREATE TABLE txn AS
        SELECT t.TransactionID AS txn_id, t.ts, t.TransactionDT AS dt, round(t.TransactionAmt, 2) AS amt,
               t.ProductCD AS product, c.card_id, t.customer_id, t.card1, t.card2, t.card3, t.card4, t.card5, t.card6,
               t.addr1, t.addr2, t.dist1, t.dist2, t.P_emaildomain AS p_email, t.R_emaildomain AS r_email,
               t.channel, t.risk_score, {C_COLS}, {D_COLS}, {M_COLS},
               d.device_id, i.id_15 AS device_status, i.id_23 AS proxy, i.id_34 AS match_status,
               i.DeviceType AS device_type
        FROM raw_t t
        JOIN card c ON c.customer_id = t.customer_id
             AND c.network IS NOT DISTINCT FROM t.card4 AND c.card_type IS NOT DISTINCT FROM t.card6
        LEFT JOIN raw_i i ON i.TransactionID = t.TransactionID
        LEFT JOIN device d ON i.TransactionID IS NOT NULL AND d.profile = coalesce(i.DeviceInfo,'?') || ' | ' || coalesce(i.id_30,'?') || ' | '
                                        || coalesce(i.id_31,'?') || ' | ' || coalesce(i.id_33,'?')
        ORDER BY c.card_id, t.ts
    """)
    con.execute("CREATE TABLE customer AS SELECT customer_id, count(*) AS n_txn, min(ts) AS first_ts FROM txn GROUP BY 1")
    con.execute(f"CREATE TABLE closed_case AS SELECT * FROM read_csv_auto('{(src / 'closed_cases_history.csv').as_posix()}', all_varchar=true)")
    con.execute("""
        CREATE TABLE closed_case_txn AS
        SELECT case_id, CAST(unnest(string_split(txn_ids, '|')) AS BIGINT) AS txn_id FROM closed_case
    """)
    con.execute("""
        CREATE TABLE closed_case_conn AS
        SELECT case_id, unnest(string_split(connected_card_ids, '|')) AS card_id
        FROM closed_case WHERE connected_card_ids IS NOT NULL
    """)
    con.execute(f"CREATE TABLE case_pack AS SELECT * FROM read_csv_auto('{(src / 'case_pack.csv').as_posix()}', all_varchar=true)")
    # Case memory written by TIGRA lives in data/memory.duckdb (see store_local.py), so this file stays read-only.
    for stmt in ("CREATE INDEX ix_txn_id ON txn(txn_id)", "CREATE INDEX ix_txn_card ON txn(card_id)",
                 "CREATE INDEX ix_txn_dev ON txn(device_id)", "CREATE INDEX ix_cct ON closed_case_txn(txn_id)"):
        con.execute(stmt)
    for tbl in ("card", "device", "txn", "customer", "closed_case", "closed_case_txn", "case_pack"):
        print(f"  {tbl:16s} {con.execute(f'SELECT count(*) FROM {tbl}').fetchone()[0]:>9,}")
    con.execute("DROP VIEW raw_t; DROP VIEW raw_i")
    con.close()
    print(f"built {DB_PATH} in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, type=Path, help="folder containing the HHGOA_IEEE CSVs")
    build(ap.parse_args().src)
