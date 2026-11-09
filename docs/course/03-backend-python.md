# 03: Backend engineering in Python

## Tooling: uv, ruff, mypy, pytest
| Tool | What it does | In this repo |
|---|---|---|
| **uv** | Fast package & Python manager (replaces pip, venv, pip-tools, pyenv). Lockfile `uv.lock` = reproducible installs. | `uv sync`, `uv run …`, `uv python install 3.12` |
| **pyproject.toml** | Single config: metadata, dependencies, optional extras (`[azure]`, `[postgres]`, `[otel]`), tool configs | root |
| **ruff** | Linter + formatter (replaces flake8, isort, black, bandit-lite). Rules selected in `[tool.ruff.lint]` | `make lint` |
| **mypy** | Static type checker. Catches `None` bugs and wrong types before runtime | `uv run mypy` |
| **pytest** | Test runner with fixtures, parametrisation, markers | `tests/`, `conftest.py` |
| **pytest-cov** | Coverage; CI fails under 75% (`fail_under`) | `--cov` |
| **moto** | In-memory fake AWS: real boto3 calls without an account | `tests/test_aws_scanners_moto.py` |
| **bandit / pip-audit** | Python SAST / known-CVE scan of dependencies | `make security` |

**Why a lockfile?** `pyproject.toml` says *what you accept* (`fastapi>=0.115`); `uv.lock` pins *exactly what you
tested*, so CI, Docker and your laptop install identical versions.

## FastAPI essentials (`src/cloud_copilot/api/`)
- **App factory** `create_app(settings, service)`: building the app in a function makes it testable (tests pass
  their own settings and service).
- **Routers** group endpoints (`routes/v1.py`, prefix `/api/v1` = API versioning).
- **Dependency injection**: `Depends(require_api_key)` runs before the handler; `Annotated[CopilotService,
  Depends(svc)]` injects the service. Easy to override in tests.
- **Pydantic request models** validate input (`ChatRequest.message: Field(min_length=1, max_length=2000)`) and
  return **422** automatically.
- **Status codes that mean something**: 201 created, 202 accepted (async scan), 401 unauthenticated, 404, 409
  conflict (scan already running), 422 validation, 429 rate limited.
- **Middleware** (`observability` in `app.py`): request ID, metrics, security headers, structured access logs.
- **Lifespan**: startup/shutdown hooks (scan-on-startup, executor shutdown).
- **OpenAPI** is generated from type hints. `/api/docs` is Swagger UI.
- **Sync vs async**: handlers here are `def` (sync) because boto3 and SQLAlchemy are blocking. FastAPI runs them
  in a thread pool. An `async def` handler doing blocking I/O would freeze the event loop. This is a classic
  interview trap.

## Pydantic v2 & settings
- `BaseModel` for data, `BaseSettings` (`config.py`) for 12-factor configuration from env vars / `.env`.
- `SecretStr` hides secrets in logs and reprs. `Field(exclude=True)` keeps `ScanResult.raw` out of JSON.
- Validators (`_split_csv`) turn `"aws,azure"` env strings into lists.

## SQLAlchemy 2.0 & Alembic (`store/`)
- **ORM models** with typed `Mapped[...]` columns; JSON columns for flexible payloads.
- **Session per unit of work** (`Database.session()` context manager commits or rolls back).
- **Repository pattern**: all SQL in one class → the rest of the code doesn't know the DB.
- **Alembic**: versioned schema migrations (`migrations/versions/0001…, 0002…`). `autogenerate` diffs models
  vs DB. Adding a NOT NULL column to an existing table needs a `server_default` (see 0002) or it fails on
  existing rows.
- **SQLite for dev, PostgreSQL in prod** via `DATABASE_URL`, same code.
- **Advisory lock** (`pg_advisory_xact_lock`) serialises migrations when several pods start together.

## Concurrency
- One `ThreadPoolExecutor(max_workers=1)` for scans + a lock → no concurrent scans in a process.
- Inside a scan, `AwsContext.for_each_region` fans out regions in a thread pool (I/O-bound → threads are fine
  despite the GIL).
- Multi-replica caveat: the in-process lock and rate limiter are per pod. At scale you'd use a queue (SQS/Redis +
  workers) and Redis for rate limits. Say this in interviews: it shows you know the limits of your design.

## Error handling philosophy
- **Fail soft per unit, fail loud overall**: one service error ≠ failed scan; status `partial` + warnings.
- Domain errors (`NotFoundError`, `AccountError`, `ScanInProgressError`) are translated to HTTP codes at the edge.
- Never leak secrets in errors (credential errors are rewritten into safe messages in `providers/accounts.py`).

## Testing strategy (the pyramid)
1. **Unit**: rules with dict fixtures (`test_rules_aws.py`), normalisers with fake SDK objects (`test_azure.py`).
2. **Integration**: scanners against moto (`test_aws_scanners_moto.py`), account connect + scan through the API
   (`test_accounts.py`).
3. **API/contract**: `TestClient` hits real routes (`test_api.py`).
4. **Catalogue invariants**: every rule has metadata, maps to compliance, runs on demo data (`test_registry.py`,
   parametrised over 103 rules).
5. **Eval**: RAG recall@3 on a golden set (`test_rag.py`).
6. **End-to-end**: kind cluster in CI (chapter 09).

## Commands
```bash
uv sync --all-extras          # install everything incl. dev tools
uv run pytest -k strategy -x  # run matching tests, stop at first failure
uv run pytest --cov           # with coverage
uv run ruff check --fix && uv run ruff format
uv run mypy
uv run alembic -c ... revision --autogenerate   # (we generate via store/migrate.alembic_config)
uv run cloud-copilot scan --fail-on CRITICAL
```

## Interview questions
1. **Why FastAPI over Flask?** Type-driven validation and OpenAPI, dependency injection, async support,
   performance; Pydantic models shared with the domain.
2. **What happens if you call a blocking library inside `async def`?** It blocks the event loop and every
   request stalls. Use `def` (thread pool) or `run_in_threadpool`.
3. **How do you test code that calls AWS?** Separate I/O from logic; unit-test logic with plain data; use moto
   or botocore Stubber for the I/O layer; never hit real accounts in CI.
4. **How do you evolve a DB schema safely?** Versioned migrations, backward-compatible steps (add nullable/default
   column → backfill → enforce), run before or at startup with a lock.
5. **What is dependency injection and why use it?** Passing collaborators in instead of creating them inside;
   enables testing with fakes and swapping implementations.
6. **How would you scale scans to 500 accounts?** Queue per account, worker pool (Celery/RQ/SQS + K8s Jobs or
   KEDA autoscaling), idempotent workers, per-account rate limiting, results merged by scan ID.

## Exercises
1. Add `GET /api/v1/rules/{rule_id}/findings` returning the latest findings for a rule, with a test.
2. Make the rate limiter use Redis (design only: where would the state live, what's the key?).
3. Write a moto test for `scan_lambda` with a function URL whose auth type is `NONE`.
