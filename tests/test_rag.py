"""RAG: chunking, BM25, RRF fusion, dense index caching, and an offline retrieval-quality eval."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cloud_copilot.rag.corpus import Chunk, chunk_markdown, load_corpus
from cloud_copilot.rag.retriever import BM25, DenseIndex, Hit, Retriever, rrf, tokenize


def test_chunking_on_headings() -> None:
    md = "# Title\n\nintro\n\n## First\nalpha\n\n## Second Part\nbeta"
    chunks = chunk_markdown("doc", md)
    assert [c.id for c in chunks] == ["doc#intro", "doc#first", "doc#second-part"]
    assert chunks[1].title == "Title — First"


def test_large_sections_are_split() -> None:
    md = "## Big\n" + "\n\n".join("word " * 120 for _ in range(6))
    assert len(chunk_markdown("d", md)) > 1


def test_tokenize_splits_rule_ids() -> None:
    assert {"s3-002", "s3", "002"} <= set(tokenize("Fix S3-002 now"))


def test_bm25_ranks_relevant_first() -> None:
    chunks = [
        Chunk("a", "a", "S3 buckets", "public bucket policy block public access"),
        Chunk("b", "b", "EC2", "security group ssh port 22"),
        Chunk("c", "c", "Kubernetes", "eks api endpoint"),
    ]
    assert BM25(chunks).search("ssh security group")[0].chunk.id == "b"
    assert BM25(chunks).search("nothing matches zzz") == []


def test_rrf_fusion() -> None:
    a, b, c = (Chunk(x, x, x, x) for x in "abc")
    fused = rrf([Hit(a, 9), Hit(b, 8)], [Hit(b, 0.9), Hit(c, 0.8)], top=3)
    assert fused[0].chunk.id == "b"


class FakeEmbeddings:
    calls = 0

    def create(self, model: str, input: list[str]) -> Any:
        FakeEmbeddings.calls += 1
        vocab = ["ssh", "bucket", "kubernetes", "cost"]
        return SimpleNamespace(
            data=[SimpleNamespace(embedding=[float(t.lower().count(v)) + 0.01 for v in vocab]) for t in input]
        )


def test_dense_index_and_cache(tmp_path: Path) -> None:
    chunks = [
        Chunk("a", "a", "ssh", "ssh ssh"),
        Chunk("b", "b", "bucket", "bucket"),
        Chunk("c", "c", "cost", "cost cost"),
    ]
    client = SimpleNamespace(embeddings=FakeEmbeddings())
    idx = DenseIndex(chunks, client, "fake", cache_dir=tmp_path)
    assert idx.search("bucket")[0].chunk.id == "b"
    before = FakeEmbeddings.calls
    DenseIndex(chunks, client, "fake", cache_dir=tmp_path)  # cached: no re-embedding of documents
    assert FakeEmbeddings.calls == before
    hybrid = Retriever(chunks, idx)
    assert hybrid.mode == "hybrid" and hybrid.search("cost")[0].chunk.id == "c"


# --------------------------------------------------------------------------- offline eval
GOLDEN = [
    ("what do I do if an access key leaked on github", "incident-response/aws-compromised-access-key"),
    ("someone made our storage bucket public, how to respond", "incident-response/data-exposure-storage"),
    ("alternative to a bastion host for ssh", "hardening/network-exposure"),
    ("service control policies multi account organizations", "hardening/aws-account-baseline"),
    ("conditional access PIM azure", "hardening/azure-subscription-baseline"),
    ("pod security network policies kyverno", "hardening/kubernetes"),
    ("savings plans reserved instances spot", "finops/cost-optimization"),
    ("sign container images cosign sbom", "devsecops/iac-and-pipeline-security"),
    ("shared responsibility model", "compliance/frameworks"),
    ("IMDSv2 instance metadata", "rules/EC2-005"),
    ("key vault purge protection", "rules/AZ-KV-001"),
    ("gp2 to gp3 migration", "rules/COST-002"),
]


@pytest.mark.eval
def test_retrieval_recall_at_3() -> None:
    retriever = Retriever(load_corpus())
    hits = 0
    misses = []
    for query, expected in GOLDEN:
        sources = [h.chunk.source for h in retriever.search(query, k=3)]
        if expected in sources:
            hits += 1
        else:
            misses.append((query, sources))
    recall = hits / len(GOLDEN)
    assert recall >= 0.9, f"recall@3={recall:.2f} misses={misses}"
