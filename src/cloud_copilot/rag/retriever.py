"""
Retrieval: BM25 (always on, zero dependencies) + optional dense embeddings, fused with Reciprocal Rank Fusion.

Dense retrieval uses any OpenAI-compatible ``/embeddings`` endpoint (Ollama ``nomic-embed-text``, OpenAI,
Azure OpenAI…). Vectors are cached on disk keyed by a content hash, so re-indexing is incremental.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cloud_copilot.log import get_logger
from cloud_copilot.metrics import RAG_RETRIEVALS
from cloud_copilot.rag.corpus import Chunk

log = get_logger(__name__)

_STOP = (
    "a an the and or of to in on for with is are be by it this that as at from how what why which do does i my "
    "we our you your can should me not no was were will would there their them they if then so"
)
STOPWORDS = frozenset(_STOP.split(" "))
TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:/-]*")


def tokenize(text: str) -> list[str]:
    toks = []
    for t in TOKEN.findall(text.lower()):
        t = t.strip(".:/-")
        if t and t not in STOPWORDS:
            toks.append(t)
            if "-" in t:  # "s3-002" also matches "s3" and "002"
                toks.extend(p for p in t.split("-") if p and p not in STOPWORDS)
    return toks


@dataclass
class Hit:
    chunk: Chunk
    score: float


class BM25:
    def __init__(self, chunks: list[Chunk], k1: float = 1.5, b: float = 0.75) -> None:
        self.chunks = chunks
        self.k1, self.b = k1, b
        self.docs = [Counter(tokenize(f"{c.title} {c.title} {' '.join(c.tags)} {c.text}")) for c in chunks]
        self.lengths = [sum(d.values()) for d in self.docs]
        self.avgdl = (sum(self.lengths) / len(self.lengths)) if self.lengths else 0.0
        df: Counter[str] = Counter()
        for d in self.docs:
            df.update(d.keys())
        n = len(chunks)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 5) -> list[Hit]:
        q = tokenize(query)
        scores: list[tuple[float, int]] = []
        for i, d in enumerate(self.docs):
            s = 0.0
            for t in q:
                if t not in d:
                    continue
                tf = d[t]
                s += (
                    self.idf[t]
                    * tf
                    * (self.k1 + 1)
                    / (tf + self.k1 * (1 - self.b + self.b * self.lengths[i] / (self.avgdl or 1)))
                )
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [Hit(self.chunks[i], s) for s, i in scores[:k]]


class DenseIndex:
    def __init__(self, chunks: list[Chunk], client: Any, model: str, cache_dir: Path | None = None) -> None:
        self.chunks, self.client, self.model = chunks, client, model
        self.cache_file = (cache_dir or Path("data")) / f"embeddings-{re.sub(r'[^a-z0-9]', '_', model.lower())}.json"
        self.vectors = self._build()

    def _embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), 64):
            resp = self.client.embeddings.create(model=self.model, input=texts[i : i + 64])
            out.extend(d.embedding for d in resp.data)
        return out

    def _build(self) -> list[list[float]]:
        cache: dict[str, list[float]] = {}
        if self.cache_file.exists():
            cache = json.loads(self.cache_file.read_text())
        keys = [hashlib.sha256(f"{c.title}\n{c.text}".encode()).hexdigest()[:24] for c in self.chunks]
        missing = [(k, c) for k, c in zip(keys, self.chunks, strict=True) if k not in cache]
        if missing:
            vecs = self._embed([f"{c.title}\n{c.text}" for _, c in missing])
            cache.update({k: v for (k, _), v in zip(missing, vecs, strict=True)})
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps({k: cache[k] for k in keys}))
            log.info("embeddings_indexed", new=len(missing), total=len(keys))
        return [cache[k] for k in keys]

    def search(self, query: str, k: int = 5) -> list[Hit]:
        q = self._embed([query])[0]
        qn = math.sqrt(sum(x * x for x in q)) or 1.0
        scored = []
        for i, v in enumerate(self.vectors):
            vn = math.sqrt(sum(x * x for x in v)) or 1.0
            scored.append((sum(a * b for a, b in zip(q, v, strict=False)) / (qn * vn), i))
        scored.sort(reverse=True)
        return [Hit(self.chunks[i], s) for s, i in scored[:k]]


def rrf(*rankings: list[Hit], k: int = 60, top: int = 5) -> list[Hit]:
    """Reciprocal Rank Fusion: robust way to merge lexical and semantic rankings without score calibration."""
    scores: dict[str, float] = {}
    by_id: dict[str, Chunk] = {}
    for ranking in rankings:
        for rank, h in enumerate(ranking):
            scores[h.chunk.id] = scores.get(h.chunk.id, 0.0) + 1.0 / (k + rank + 1)
            by_id[h.chunk.id] = h.chunk
    ordered = sorted(scores.items(), key=lambda kv: -kv[1])[:top]
    return [Hit(by_id[cid], s) for cid, s in ordered]


class Retriever:
    def __init__(self, chunks: list[Chunk], dense: DenseIndex | None = None) -> None:
        self.chunks = chunks
        self.bm25 = BM25(chunks)
        self.dense = dense

    @property
    def mode(self) -> str:
        return "hybrid" if self.dense else "bm25"

    def search(self, query: str, k: int = 5) -> list[Hit]:
        RAG_RETRIEVALS.labels(mode=self.mode).inc()
        lexical = self.bm25.search(query, k=k * 3)
        if not self.dense:
            return lexical[:k]
        try:
            return rrf(lexical, self.dense.search(query, k=k * 3), top=k)
        except Exception as exc:  # embedding endpoint down -> degrade gracefully
            log.warning("dense_retrieval_failed", error=type(exc).__name__)
            return lexical[:k]


def build_retriever(settings: Any) -> Retriever:
    from cloud_copilot.rag.corpus import load_corpus

    chunks = load_corpus(settings.knowledge_dir)
    dense = None
    if settings.embeddings_base_url:
        try:
            from openai import OpenAI

            key = settings.embeddings_api_key.get_secret_value() if settings.embeddings_api_key else "unused"
            client = OpenAI(base_url=settings.embeddings_base_url, api_key=key, timeout=30, max_retries=1)
            dense = DenseIndex(chunks, client, settings.embeddings_model)
        except Exception as exc:
            log.warning("dense_index_unavailable", error=f"{type(exc).__name__}: {exc}")
    log.info("retriever_ready", chunks=len(chunks), mode="hybrid" if dense else "bm25")
    return Retriever(chunks, dense)
