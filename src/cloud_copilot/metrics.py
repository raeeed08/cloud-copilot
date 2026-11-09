"""Prometheus metrics (exposed on /metrics)."""

from prometheus_client import Counter, Gauge, Histogram

SCANS = Counter("copilot_scans_total", "Scans executed", ["status", "trigger"])
SCAN_DURATION = Histogram(
    "copilot_scan_duration_seconds", "Scan duration", buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200)
)
FINDINGS = Gauge("copilot_findings", "Active findings in the latest scan", ["provider", "severity"])
POSTURE_SCORE = Gauge("copilot_posture_score", "Posture score of the latest scan (0-100)")
SAVINGS = Gauge("copilot_estimated_monthly_savings_usd", "Estimated monthly savings in the latest scan")
SERVICE_ERRORS = Counter("copilot_service_errors_total", "Scanner failures", ["provider", "service"])

LLM_REQUESTS = Counter("copilot_llm_requests_total", "LLM calls", ["model", "outcome"])
LLM_LATENCY = Histogram("copilot_llm_latency_seconds", "LLM latency", ["model"], buckets=(0.5, 1, 2, 5, 10, 20, 45, 90))
LLM_TOKENS = Counter("copilot_llm_tokens_total", "LLM tokens", ["model", "kind"])
RAG_RETRIEVALS = Counter("copilot_rag_retrievals_total", "Knowledge-base retrievals", ["mode"])
