# 10: Observability

## The three signals (+1)
- **Metrics**: cheap numeric time series, great for alerts and trends (Prometheus).
- **Logs**: discrete events with context; **structured JSON** so they can be queried (we use `structlog`).
- **Traces**: a request's path across services with timings (OpenTelemetry → Jaeger/Tempo/X-Ray).
- **Profiles** (+1): where CPU/memory goes (Pyroscope). Optional.

## What the app exposes
`/metrics` (Prometheus text format) from `src/cloud_copilot/metrics.py` and `api/app.py`:
| Metric | Type | Use |
|---|---|---|
| `copilot_http_requests_total{method,route,status}` | counter | traffic, error rate |
| `copilot_http_request_seconds_bucket{route}` | histogram | latency percentiles |
| `copilot_scans_total{status,trigger}` / `copilot_scan_duration_seconds` | counter / histogram | scan health |
| `copilot_findings{provider,severity}` / `copilot_posture_score` | gauges | security posture as a metric |
| `copilot_estimated_monthly_savings_usd` | gauge | FinOps |
| `copilot_service_errors_total{provider,service}` | counter | missing permissions, API failures |
| `copilot_llm_requests_total{model,outcome}`, `copilot_llm_latency_seconds`, `copilot_llm_tokens_total` | | LLM reliability and cost |
| `copilot_rag_retrievals_total{mode}` | counter | RAG usage |

Metric types: **counter** (only goes up; use `rate()`), **gauge** (up/down), **histogram** (buckets →
`histogram_quantile`), summary (client-side quantiles; avoid for aggregation).
**Cardinality**: never put unbounded values (user IDs, resource names) in labels; it explodes memory. We label by
`route` template, not raw path.

Logs: JSON with `request_id` bound per request (`structlog.contextvars`), echoed in the `X-Request-ID` header
so a user's error can be traced to its log lines. Traces: set `OTEL_EXPORTER_OTLP_ENDPOINT`
(`docker compose --profile tracing up`) and FastAPI is auto-instrumented.

## PromQL you should be able to write
```promql
sum(rate(copilot_http_requests_total{status=~"5.."}[5m])) / sum(rate(copilot_http_requests_total[5m]))   # error ratio
histogram_quantile(0.95, sum by (le, route) (rate(copilot_http_request_seconds_bucket[5m])))             # p95 latency
sum by (severity) (copilot_findings)                                                                    # posture
increase(copilot_service_errors_total[1h]) > 0                                                          # broken scanner
```

## Alerts (`deploy/compose/prometheus/alerts.yml`, Helm `PrometheusRule`)
Critical findings open, posture score dropped >10 points in a day, scanner errors, no scan in 48h, LLM error
rate >50%, API p95 >2s. Good alerts are **actionable, symptom-based, low-noise**, with a runbook link. `for:` avoids
flapping.

## SLI / SLO / error budget
- **SLI**: measured indicator, e.g. "% of API requests < 500 ms and not 5xx".
- **SLO**: target, e.g. 99.5% over 30 days. **Error budget** = 0.5% → spend it on releases; when exhausted, freeze
  features and fix reliability.
- **RED** (Rate, Errors, Duration) for services; **USE** (Utilisation, Saturation, Errors) for resources.

## Grafana
Provisioned as code: datasource (`provisioning/datasources`) and the dashboard JSON
(`deploy/compose/grafana/dashboards/cloud-copilot.json`): score, critical findings, savings, latency, LLM health.

## Commands
```bash
curl -s localhost:8000/metrics | grep copilot_posture_score
open http://localhost:9090/graph       # Prometheus: try the PromQL above
open http://localhost:9090/alerts      # alert states
open http://localhost:3000             # Grafana → Cloud Copilot folder
docker compose logs api | jq 'select(.level=="warning")'
```

## Interview questions
1. **Metrics vs logs vs traces?** Aggregates for alerting vs detailed events vs request flow across services.
2. **What is high cardinality and why is it dangerous?** Too many label combinations → memory/cost blow-up.
3. **How do you define an SLO for this API?** Availability and latency SLIs from the HTTP histogram; 99.5%/30d;
   burn-rate alerts.
4. **Counter vs gauge?** Monotonic (rate over time) vs current value.
5. **How do you correlate a user error to logs?** Request ID propagated in headers, logs and traces.

## Exercises
1. Write an alert "scan duration p95 > 5 minutes" and load it into Prometheus.
2. Add a Grafana panel for `copilot_scans_total` by status.
3. Run with tracing and find the slowest span of `GET /api/v1/plan`.
