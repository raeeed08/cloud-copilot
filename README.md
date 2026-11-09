# Cloud Copilot

**Multi-cloud security & FinOps posture platform with an AI copilot.**
Connect an AWS or Azure account, scan it with 103 rules mapped to CIS and NIST, and get **attack paths**
(chained weaknesses mapped to MITRE ATT&CK) plus a **phased remediation strategy** with console deep links.
Fix, re-scan to verify, and add guardrails so the issues don't come back. A RAG-grounded LLM explains everything,
and an MCP server exposes it all to AI agents. It ships with a
full production DevOps stack: Docker, Helm, Argo CD, Terraform (EKS and Azure Container Apps), signed
images, and Prometheus/Grafana.

[![CI](https://github.com/raeeed08/cloud-copilot/actions/workflows/ci.yml/badge.svg)](https://github.com/raeeed08/cloud-copilot/actions/workflows/ci.yml)
[![Release](https://github.com/raeeed08/cloud-copilot/actions/workflows/release.yml/badge.svg)](https://github.com/raeeed08/cloud-copilot/actions/workflows/release.yml)
[![CodeQL](https://github.com/raeeed08/cloud-copilot/actions/workflows/codeql.yml/badge.svg)](https://github.com/raeeed08/cloud-copilot/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

![Overview](docs/img/overview.png)

## Highlights

| | |
|---|---|
| **End-to-end flow** | connect accounts in the UI (AWS assume-role / keys / profile, Azure service principal; secrets Fernet-encrypted) → scan → **attack paths** → **phased strategy** (today / week / month / guardrails) → "Open in AWS console / Azure portal" → re-scan → **resolved diff** and score trend |
| **Practice labs** | `infra/terraform/lab-aws` and `lab-azure` deploy deliberately misconfigured, near-free resources and a read-only scanner identity; `-var secure=true` applies the fixes |
| **Rule engine** | 103 rules (70 AWS · 33 Azure) over 27 scanners: IAM, S3, EC2/EBS/VPC, CloudTrail, RDS, KMS, Lambda, GuardDuty/Config/Security Hub, ELB, EKS, ECR, DynamoDB, Secrets Manager, SQS/SNS, CloudWatch Logs, ACM · Storage, NSG, Key Vault, SQL, VMs/disks, App Service, Monitor, Defender, AKS, ACR |
| **Coverage** | every enabled region in parallel, every subscription, pagination, adaptive retries, per-service fault isolation |
| **Compliance** | CIS AWS Foundations v3.0, CIS Azure v2.0, NIST 800-53 r5 control status |
| **FinOps** | Cost Explorer / Azure Cost Management spend + 10 waste rules with estimated monthly savings |
| **AI copilot** | provider configurable in the UI (Groq, OpenRouter, OpenAI, Ollama, any OpenAI-compatible) with live connection test · strategy briefing and chat grounded by **RAG** (BM25 + optional embeddings, RRF) over playbooks and rule docs, with citations · model fallback chain · PII/ID **redaction** · prompt-injection guardrails · works offline |
| **MCP server** | 11 tools (incl. `get_attack_paths`, `get_remediation_plan`), 2 resources, 1 prompt, so Claude, Cursor or any agent can triage your cloud (stdio and streamable HTTP) |
| **Workflow** | scan history and trend, suppressions with reason and expiry, CSV/Markdown export, Terraform fix per finding, `--fail-on CRITICAL` CI gate |
| **DevOps** | multi-stage non-root image · Compose (Postgres, Prometheus, Grafana, Ollama, Jaeger) · Helm (HPA, PDB, CronJob, NetworkPolicy, ServiceMonitor, External Secrets, IRSA/WI) · Argo CD ApplicationSet · Terraform AWS (VPC, EKS, ECR, OIDC) and Azure (Container Apps, ACR, Key Vault) |
| **Supply chain** | GitHub Actions: ruff, mypy, pytest (309 tests, 88% coverage), Bandit, pip-audit, npm audit, gitleaks, Trivy, Checkov, tflint, kubeconform, CodeQL, e2e on **kind**, multi-arch build, **cosign** keyless signing, SBOM, SLSA provenance, GitOps promotion |

## Quick start (no cloud account needed)

```bash
# 1. local dev: demo estate, API + dashboard on http://localhost:8000
make install && make dev

# 2. or the full platform in containers
cp .env.example .env
docker compose up -d --build    # app :8000 · Grafana :3000 · Prometheus :9090 · MCP :8765/mcp
```

`DEMO_MODE=true` scans a synthetic AWS + Azure estate with the **real** engine, so every screen works without
credentials. Set `LLM_API_KEY` (OpenRouter, Groq, OpenAI…) or run `docker compose --profile local-llm up` for a
local Ollama. Without a model the copilot still answers from the rule engine and knowledge base.

## From zero to a verified fix (real account)

1. **Deploy the practice lab** in an AWS account you own: [`infra/terraform/lab-aws`](infra/terraform/lab-aws/README.md)
   (or [`lab-azure`](infra/terraform/lab-azure/README.md)).
2. **Settings → AI provider**: pick Groq, paste a key, click *Save & test*.
3. **Accounts → Connect**: paste the role ARN, external ID and keys from `terraform output`, then *Connect & verify*.
4. **Run scan**, open **Strategy**: break the attack paths first, follow the phases; every action links to the
   resource in the console.
5. Fix (console or `terraform apply -var secure=true`), **Re-scan to verify**: resolved findings are listed and
   the score rises.
6. Apply the suggested **guardrails** (SCP / Azure Policy / CI checks) so it doesn't happen again.

![Strategy](docs/img/strategy.png)

## Scan real accounts from the CLI

```bash
export DEMO_MODE=false
aws sso login --profile audit && export AWS_PROFILE=audit    # read-only: SecurityAudit + ViewOnlyAccess
az login                                                     # Reader + Security Reader + Cost Management Reader
uv run cloud-copilot scan --fail-on CRITICAL
```

The Terraform modules `infra/terraform/modules/aws-scanner-role` and `azure-scanner-identity` create exactly
these read-only identities (IRSA / workload identity / cross-account trust).

## Use it from an AI agent (MCP)

```bash
claude mcp add cloud-copilot -- uv --directory $PWD run cloud-copilot mcp
```
> *"Use cloud-copilot to triage my posture and give me the five most urgent fixes with Terraform."*

More clients: [examples/mcp-clients.md](examples/mcp-clients.md).

## Screens

| Findings | Compliance | Cost |
|---|---|---|
| ![](docs/img/findings.png) | ![](docs/img/compliance.png) | ![](docs/img/cost.png) |
| **Accounts** | **AI provider** | **Inventory** |
| ![](docs/img/accounts.png) | ![](docs/img/settings.png) | ![](docs/img/inventory.png) |

## Architecture

```mermaid
flowchart LR
  AWS & Azure -->|read-only| Scanners --> Rules[Rule engine · 103 rules] --> Corr[Attack-path correlation] --> Plan[Strategy] --> Service --> DB[(Postgres)]
  Service --> LLM[LLM gateway<br/>fallback · redaction]
  KB[RAG<br/>BM25 + embeddings] --> LLM
  API[FastAPI + React] & MCP[MCP server] & Cron[CronJob / CLI] --> Service
  API --> Prom[Prometheus/Grafana]
```

📚 **Learn it from zero to hero:** [the Cloud Copilot course](docs/course/README.md) (15 chapters + interview prep).

Details: [architecture](docs/architecture.md) · [threat model](docs/threat-model.md) ·
[rule catalogue](docs/rules.md) · [ADRs](docs/adr) · [security policy](SECURITY.md)

## Deploy

| Target | Command |
|---|---|
| Kubernetes (any) | `helm upgrade --install cc deploy/helm/cloud-copilot -f deploy/helm/cloud-copilot/values-demo.yaml` |
| Local kind cluster | `make kind` |
| AWS (EKS + Argo CD) | `cd infra/terraform/aws && terraform init -backend-config=backend.hcl && terraform apply`, then `kubectl apply -f deploy/argocd/` |
| Azure Container Apps | `cd infra/terraform/azure && terraform apply -var subscription_id=…` |
| CI only | enable `.github/workflows/posture-scan.yml` with `AWS_SCANNER_ROLE_ARN` (GitHub OIDC) |

Release flow: merge to `main` → image built (amd64/arm64), Trivy-scanned, cosign-signed, SBOM + provenance
attested → digest committed to `deploy/environments/staging.yaml` → Argo CD syncs staging → PR promotes prod.

## Develop

```bash
make check      # ruff, mypy, eslint, 309 tests + RAG eval, bandit, pip-audit, npm audit
make tf-check   # terraform fmt/validate (all stacks)
make docs       # regenerate docs/rules.md from the registry
```

Adding a check is one decorated function. The API, dashboard, compliance view, knowledge base and MCP pick it up
automatically:

```python
@rule(id="S3-004", title="S3 bucket allows plain HTTP", provider=AWS, service="s3",
      severity=Severity.MEDIUM, cis=["2.1.1"], nist=["SC-8"],
      description="...", remediation="...", terraform='...')
def tls_only(d):
    for b in d["buckets"]:
        if not b["policy"]["enforces_tls"]:
            yield Hit(f"arn:aws:s3:::{b['name']}", f"Bucket '{b['name']}' does not enforce TLS.")
```

## Tech stack
Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2 + Alembic · boto3 · Azure SDK · OpenAI-compatible LLMs ·
MCP SDK · React 18 + TypeScript + Vite · uv · Docker · Helm · Argo CD · Terraform · GitHub Actions · Prometheus ·
Grafana · OpenTelemetry · moto · pytest

## License
MIT
