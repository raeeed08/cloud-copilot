# ADR 0004: Provider-agnostic LLM gateway with redaction and graceful degradation

**Status:** accepted

## Decision
- Any OpenAI-compatible endpoint, configured via `LLM_BASE_URL` / `LLM_MODELS` (ordered fallback chain).
- Retries only on transient errors (408/409/429/5xx, timeouts), with a hard stop on 401/403.
- Identifiers are pseudonymised before sending and restored after.
- Prompt-injection guardrails: data in delimited blocks, explicit instruction hierarchy, chat has no tools.
- Without a model, every feature returns a deterministic answer built from the rule engine and the knowledge
  base.

## Consequences
The product works (and can be demoed) with no API key, and switching to a self-hosted model is configuration only.
