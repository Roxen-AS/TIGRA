"""Runtime configuration, read once from the environment (and an optional backend/.env file)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv(BACKEND / ".env")

DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "fraud.duckdb"
CASES_DIR = ROOT / "cases"
DOCS_DIR = ROOT / "docs" / "kb"

# Graph backend: "tigergraph" when TG_HOST is set, otherwise the embedded DuckDB mirror.
TG_HOST = os.getenv("TG_HOST", "")
TG_GRAPH = os.getenv("TG_GRAPH", "TigraGraph")
TG_SECRET = os.getenv("TG_SECRET", "")
TG_USERNAME = os.getenv("TG_USERNAME", "tigergraph")
TG_PASSWORD = os.getenv("TG_PASSWORD", "")
GRAPH_BACKEND = os.getenv("GRAPH_BACKEND", "tigergraph" if TG_HOST else "local")

# LLM (optional). Used for synthesis/explanation only; every decision is grounded in graph evidence + policy.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-5")
LLM_ENABLED = bool(ANTHROPIC_API_KEY) and os.getenv("LLM_ENABLED", "1") != "0"
