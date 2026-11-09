# Architecture

## Components

```mermaid
flowchart LR
  subgraph Clouds["Cloud accounts (read-only)"]
    AWS["AWS<br/>17 services · all regions"]
    AZ["Azure<br/>10 services · all subscriptions"]
  end

  subgraph Copilot["Cloud Copilot (one container image)"]
    direction TB
    SC["Scanners<br/>normalise → plain dicts"]
    RE["Rule engine<br/>103 pure-function rules<br/>CIS / NIST mapping"]
    SV["Service layer<br/>scan lifecycle · scoring · suppressions"]
    DB[("PostgreSQL / SQLite<br/>scans · findings · suppressions")]
    RAG["RAG<br/>BM25 + optional embeddings (RRF)<br/>playbooks + rule docs"]
    LLM["LLM gateway<br/>fallback chain · retries · redaction"]
    API["FastAPI REST + React dashboard"]
    MCP["MCP server<br/>9 tools · 2 resources · 1 prompt"]
    CLI["CLI / CronJob<br/>scan --fail-on CRITICAL"]
  end

  AWS & AZ --> SC --> RE --> SV --> DB
  SV --> LLM
  RAG --> LLM
  API & MCP & CLI --> SV
  LLM -->|"pseudonymised context"| Provider["OpenRouter · Groq · OpenAI · Ollama"]
  Users["Engineers"] --> API
  Agents["Claude / Cursor / agents"] --> MCP
  API -->|/metrics| Prom["Prometheus → Grafana / alerts"]
```

## Scan pipeline

1. **Context.** `AwsContext` resolves credentials (env, SSO, IRSA, instance role), the account ID and enabled
   regions. `AzureContext` uses `DefaultAzureCredential` (CLI, managed identity, workload identity).
   A missing provider raises `NotConfiguredError`, so its services are **skipped**, not failed.
2. **Scanners** (`@scanner(provider, service)`) fan out per region in a thread pool with adaptive retries.
   Region-level `AccessDenied`/`OptInRequired` become *warnings* (service status `partial`), never crashes.
3. **Rules** (`@rule(...)`) are pure functions `data -> Iterable[Hit]`. One buggy rule only marks its service
   `partial`. Every rule carries severity, category, rationale, remediation, Terraform, CIS and NIST controls.
4. **Findings** get a stable ID `sha256(rule|resource|region|account)`, so suppressions survive re-scans.
5. **Score** = severity-weighted share of *evaluated* security/reliability controls that pass.
6. **Persistence and metrics.** The scan, its findings and per-service health are stored, and Prometheus
   gauges are updated.
7. **AI briefing.** The top 30 findings (compact, pseudonymised) go to the LLM gateway. If no model is
   reachable, a deterministic report is generated instead.

## From findings to strategy

```mermaid
flowchart LR
  F[Findings] --> C[Correlation<br/>attack paths + MITRE ATT&CK]
  R[(Raw scanner data<br/>instance→SG, DB→SG, users)] --> C
  C --> P[Strategy engine]
  F --> P
  P --> N[Today: break paths, CRITICAL exposure]
  P --> W[This week: identity & data]
  P --> M[This month: detection & resilience]
  P --> H[Hygiene] & S[Save money] & G[Guardrails: SCP / Azure Policy / CI]
  N & W & M -->|fix + re-scan| D[Diff: resolved / new / persisting]
```

* **Correlation** (`core/correlation.py`) walks the raw normalised data per account, e.g. *instance with public
  IP* → *its security groups expose SSH* → *IMDSv1* → *instance role*, and emits a scenario with steps, MITRE
  technique IDs, impact and the single change that breaks the chain.
* **Strategy** (`core/strategy.py`) groups findings per rule into actions, assigns a phase (chain-breakers and
  CRITICAL first), estimates effort (S/M/L) and the exact posture-score gain, and picks guardrails for the rule
  families that failed. Deterministic and explainable; the LLM only narrates it.
* **Verification** (`Repository.diff`) compares a scan with the previous scan of the same targets.

## Connected accounts

Credentials are entered in the UI and stored **Fernet-encrypted** (`crypto.py`, key from `SECRET_KEY`); the API
returns only masked hints. `providers/accounts.py` turns an account into a scan context: AWS `assume_role`
(STS AssumeRole with External ID, recommended), `access_keys`, `profile` or ambient; Azure service principal or
`DefaultAzureCredential`. *Verify* calls STS `GetCallerIdentity` / lists subscriptions and stores the identity
and console sign-in URL. A scan can target any set of accounts; results are merged and re-scored.

## Copilot chat (RAG)

```mermaid
sequenceDiagram
  participant U as User / agent
  participant S as Service
  participant R as Retriever
  participant G as LLM gateway
  U->>S: question + short history
  S->>R: BM25 (+ dense) search over playbooks & rule docs
  S->>S: BM25 over findings → top 15 relevant (severity top-up)
  S->>S: Redactor: account IDs, ARNs, IPs, emails, key IDs → tokens
  S->>G: system guardrails + <scan>/<findings>/<knowledge> data blocks
  G-->>S: answer (fallback across models, retries on 429/5xx)
  S->>S: restore tokens
  S-->>U: Markdown answer + citations + finding IDs
```

Retrieval quality is guarded by an offline eval (`tests/test_rag.py::test_retrieval_recall_at_3`, a golden
set of 12 questions, recall@3 ≥ 0.9) that runs in CI like any other test.

## Deployment topologies

| Target | How | Identity |
|---|---|---|
| Laptop | `make dev` or `docker compose up` (app, Postgres, Prometheus, Grafana, MCP; optional Ollama, Jaeger) | AWS profile / `az login` |
| Kubernetes (EKS/AKS) | Helm chart, Argo CD ApplicationSet (staging auto-sync, prod manual) | IRSA / Workload Identity |
| Serverless containers | Terraform `infra/terraform/azure` → Azure Container Apps + Key Vault | User-assigned managed identity |
| CI only | `.github/workflows/posture-scan.yml` nightly with `--fail-on CRITICAL` | GitHub OIDC → read-only role |

## Repository map

```
src/cloud_copilot/
  core/            registry (rules + scanners), engine, scoring
  providers/aws/   context, 4 scanner modules (17 services), 5 rule modules, Cost Explorer
  providers/azure/ context, scanners (10 services), rules, Cost Management
  providers/demo   synthetic estate used for demos and end-to-end tests
  llm/             gateway (fallback, retries, metrics), redaction, advisor (briefing + chat)
  rag/             corpus/chunking, BM25, dense index, RRF
  store/           SQLAlchemy models, repository, Alembic migrations
  api/             FastAPI app, security (API keys, rate limit), routes
  mcp/             MCP server
web/               React + TypeScript dashboard (Vite → served by FastAPI)
knowledge/         RAG playbooks (incident response, hardening, FinOps, DevSecOps, compliance)
deploy/            Compose stack, Helm chart, Argo CD, environment values, Grafana/Prometheus
infra/terraform/   AWS (VPC, EKS, ECR, IRSA, GitHub OIDC, Argo CD, ESO) · Azure (Container Apps, ACR, KV)
.github/workflows/ CI, release (sign/SBOM/provenance), CodeQL, nightly posture scan
```
