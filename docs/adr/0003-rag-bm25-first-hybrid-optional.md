# ADR 0003: BM25-first retrieval, optional dense embeddings fused with RRF

**Status:** accepted

## Context
The copilot needs grounded answers (playbooks, rule rationale). Vector databases add operational weight, and
many deployments have no embedding endpoint.

## Decision
A zero-dependency BM25 index is always on. If `EMBEDDINGS_BASE_URL` is set (Ollama, OpenAI, Azure OpenAI), a dense
index is built (cached on disk by content hash) and fused with BM25 using Reciprocal Rank Fusion. If the dense
side fails at query time, retrieval degrades to BM25.

## Consequences
- Works offline and in CI. Retrieval quality is measured by a golden-set recall@3 test.
- The corpus is small (about 150 chunks), so brute-force cosine is fine. Move to pgvector or Qdrant beyond ~50k
  chunks.
