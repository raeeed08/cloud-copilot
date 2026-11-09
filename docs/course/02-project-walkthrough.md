# 02: Project walkthrough: follow one scan end to end

## The big picture
```
browser (React) ──HTTP──▶ FastAPI routes ──▶ CopilotService ──▶ ScanEngine ──▶ scanners ──▶ AWS/Azure APIs
                                   │                │                 └──▶ rules ──▶ findings
                                   │                ├──▶ correlation (attack paths) ──▶ strategy (plan)
                                   │                ├──▶ Copilot (LLM briefing, RAG)
                                   │                └──▶ Repository ──▶ PostgreSQL/SQLite
                                   └──▶ /metrics (Prometheus)      MCP server and CLI reuse CopilotService
```
Layering rule: **transport** (API, CLI, MCP) → **service** (orchestration) → **domain** (engine, rules,
correlation, strategy) → **infrastructure** (boto3/Azure SDK, database, LLM). Inner layers never import outer
ones. That's why the same scan works from a button, a CronJob, a CLI or an AI agent.

## Step by step: clicking "Run scan"
1. **UI**: `web/src/App.tsx` → `runScan()` → `api.startScan({account_ids})` (`web/src/api.ts`) → `POST /api/v1/scans`.
2. **Route**: `src/cloud_copilot/api/routes/v1.py::create_scan`. Auth dependency `require_api_key`
   (`api/security.py`), rate limit, then `CopilotService.start_scan`. Returns **202 Accepted** with the scan ID:
   long work is never done inside the HTTP request.
3. **Service** (`service.py`): `resolve_targets()` decides *what* to scan (demo / connected accounts / ambient
   credentials). A lock guarantees one scan at a time (**409** otherwise). The scan row is created as `queued` and
   the work is submitted to a background thread pool.
4. **Per target**: `_scan_target()` decrypts the account's credentials (`store/accounts.py` + `crypto.py`),
   builds a context (`providers/accounts.py`: STS AssumeRole with External ID, or keys, or profile) and runs a
   `ScanEngine` (`core/engine.py`).
5. **Engine**: for each registered scanner (`@scanner` in `providers/aws/scanners/*.py`), call it, isolating
   failures: `NotConfiguredError` → service *skipped*, any other exception → service *error*, region-level
   AccessDenied → *partial* with a warning (`AwsContext.for_each_region` in `providers/aws/context.py`). Then run
   every `@rule` of that service (pure functions over plain dicts) → `Finding` objects with stable IDs, Terraform
   and a console URL (`providers/console.py`).
6. **Merge & score**: results of all targets are merged (`service.merge`). Score = severity-weighted share of
   passing controls (`engine.score`).
7. **Correlate**: `core/correlation.py` walks the raw data (instances → security groups, DBs → security groups,
   users → policies) and emits attack paths.
8. **Strategy & briefing**: `core/strategy.py::build_plan` builds phases; `llm/advisor.py::explain_scan` asks the
   LLM to narrate it (or writes a deterministic version if no LLM is available).
9. **Persist**: `store/repository.py::save_result` (scan row + one row per finding, JSON payload). Prometheus
   gauges are updated (`metrics.py`).
10. **UI polling**: the browser polls `GET /api/v1/scans/{id}` until the status isn't `queued`/`running`, then reloads
    findings, plan (`GET /api/v1/plan`, which also computes the **diff** with the previous scan), compliance, trend.

## The registry pattern (the heart of the design)
```python
@scanner(Provider.AWS, "s3", "S3 buckets")           # I/O: read and normalise
def scan_s3(ctx) -> dict: ...

@rule(id="S3-004", title=..., provider=AWS, service="s3", severity=Severity.MEDIUM,
      cis=["2.1.1"], nist=["SC-8"], description=..., remediation=..., terraform=...)
def tls_only(d: dict) -> Iterator[Hit]:               # logic: pure function, trivially testable
    ...
```
Decorators fill two dicts (`core/registry.py`). Everything else (API catalogue, docs, knowledge base, compliance
view, MCP `list_rules`) reads from them. **Open/closed principle**: add behaviour without modifying the engine.

## Data model (`models.py`)
`Finding` (rule, severity, resource, region, account, message, remediation, terraform, compliance, savings,
console_url, suppressed) · `ServiceResult` (status, duration, warnings) · `ScanResult` (findings, services,
inventory, costs, score, scenarios, raw data excluded from serialisation) · `RuleInfo`.
Pydantic gives validation and JSON for free. The same models go to the API, the DB payload and the MCP.

## Persistence (`store/`)
- `db.py`: SQLAlchemy 2.0 typed models: `scans`, `findings`, `suppressions`, `cloud_accounts`, `app_settings`.
- `migrations/`: Alembic. Migrations run at startup under a **PostgreSQL advisory lock** so several replicas
  can't race (`store/migrate.py`).
- `repository.py`: the only place that writes SQL. Diff = set operations on finding IDs between two scans.

## Security inside the app
- API keys compared in constant time, required in prod; rate limits on scan, chat and LLM test.
- Strict CSP + `nosniff` + `frame-ancestors 'none'`; React escapes output; Markdown without raw HTML.
- Cloud and AI secrets encrypted with Fernet (`crypto.py`), never returned (masked hints only).
- LLM prompts pseudonymised (`llm/redaction.py`) and fenced as untrusted data.

## Exercises (do them: they're the best interview prep)
1. **Add a rule**: "S3 bucket has no MFA delete" (`b["mfa_delete"]` already exists in the scanner). Add it to
   `providers/aws/rules/data.py`, give it a CIS/NIST mapping, add demo data, run `make test`. Watch it appear in
   the dashboard, the strategy, `docs/rules.md` (`make docs`) and the MCP `list_rules`, with no other change.
2. **Add an attack path**: "public Lambda + over-privileged role" in `core/correlation.py` with a test in
   `tests/test_intelligence.py`.
3. Trace `GET /api/v1/plan` from route to SQL with the debugger (VS Code: *Run → Python Debugger: FastAPI*).
4. Explain to a rubber duck why the scan runs in a thread pool and returns 202 instead of 200.
