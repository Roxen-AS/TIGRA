"""Document side of GraphRAG: fraud policy, typologies, regulatory guidance and closed-case narratives.

Embeddings are a deterministic signed-hashing bag of uni/bi-grams (512 dims, L2-normalised). They need no model
download and no API key, and they are the same vectors that `tigergraph/load_tg.py` writes into the
TigerGraph vector attribute `Doc.embedding`, so local retrieval and TigerGraph `vectorSearch` agree.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from .config import DOCS_DIR

DIM = 512
_TOKEN = re.compile(r"[a-z0-9$]+(?:\.[0-9]+)?")
_STOP = frozenset("a an the and or of to in on for is are be by with as at it this that from when any not no its their".split())


def _h(tok: str) -> tuple[int, float]:
    d = hashlib.blake2b(tok.encode(), digest_size=8).digest()
    return int.from_bytes(d[:4], "little") % DIM, (1.0 if d[4] & 1 else -1.0)


def embed(text: str) -> np.ndarray:
    toks = [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]
    v = np.zeros(DIM, dtype=np.float32)
    for gram in toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]:
        i, s = _h(gram)
        v[i] += s
    n = np.linalg.norm(v)
    return v / n if n else v


@dataclass(frozen=True)
class Doc:
    doc_id: str
    title: str
    text: str
    source: str  # file name or closed case id


def _chunk_markdown(name: str, md: str) -> list[Doc]:
    docs, title, buf = [], name, []

    def flush():
        body = "\n".join(buf).strip()
        if body:
            docs.append(Doc(f"{name}#{len(docs)}", title, body, name))

    for line in md.splitlines():
        if line.startswith("#"):
            flush()
            title, buf = line.lstrip("#").strip(), []
        elif re.match(r"^\*\*(R\d+|\d+)\.", line):  # policy rules / numbered patterns become their own chunks
            flush()
            title, buf = re.sub(r"\*\*", "", line.split(".", 1)[0]).strip() + " " + line.split("**")[1].split(".", 1)[-1].strip(), [line]
        else:
            buf.append(line)
    flush()
    return docs


class KnowledgeBase:
    def __init__(self, closed_case_notes: list[dict] | None = None):
        docs: list[Doc] = []
        for p in sorted(DOCS_DIR.glob("*.md")):
            docs += _chunk_markdown(p.stem, p.read_text(encoding="utf-8"))
        # Closed-case narratives: one representative per (outcome, pattern, note template) keeps the index small.
        seen = set()
        for r in closed_case_notes or []:
            key = (r["pattern"], re.sub(r"[\d$.,]+|C\d{5}(-K\d)?|CC-\d+", "#", r["analyst_notes"])[:160])
            if key in seen:
                continue
            seen.add(key)
            docs.append(Doc(f"case:{r['case_id']}", f"{r['case_id']} ({r['outcome']}, {r['pattern']})", r["analyst_notes"], r["case_id"]))
        self.docs = docs
        self.matrix = np.stack([embed(d.title + " " + d.text) for d in docs]) if docs else np.zeros((0, DIM))

    def search(self, query: str, k: int = 4, source_prefix: str | None = None) -> list[dict]:
        if not self.docs:
            return []
        sims = self.matrix @ embed(query)
        order = np.argsort(-sims)
        out = []
        for i in order:
            d = self.docs[i]
            if source_prefix and not d.doc_id.startswith(source_prefix):
                continue
            out.append({"doc_id": d.doc_id, "title": d.title, "score": round(float(sims[i]), 3), "text": d.text[:700]})
            if len(out) == k:
                break
        return out

    @lru_cache(maxsize=64)
    def rule(self, rule_id: str) -> str:
        """Exact policy text for a rule id like 'R5' (used to cite the rule in explanations)."""
        for d in self.docs:
            if d.source == "fraud_policy" and d.title.startswith(rule_id + " "):
                return d.text
        return ""
