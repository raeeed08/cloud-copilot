# Cloud Copilot: from zero to hero

A course built around **your** project. Every concept is tied to a file you can open, a command you can run and
an interview question you will be asked. By the end you should be able to explain every line of this repository
and defend every design choice.

## How to use it
- Read one chapter, then open the files it points to and **run the commands**. Reading alone won't stick.
- Do the exercises at the end of each chapter. They are small and each one changes the project.
- Answer the interview questions **out loud** before reading the model answer. Interviews test recall under
  pressure, not recognition.
- Keep a notebook of "things I couldn't explain". That list is your revision plan.

## Syllabus

| # | Chapter | You will be able to… |
|---|---|---|
| 01 | [Cloud security foundations](01-cloud-security-foundations.md) | explain IAM, network exposure, encryption, logging, CSPM, CIS/NIST, MITRE ATT&CK |
| 02 | [Project walkthrough](02-project-walkthrough.md) | follow one scan from the button click to the database and back |
| 03 | [Backend engineering in Python](03-backend-python.md) | explain FastAPI, Pydantic, SQLAlchemy, Alembic, pytest/moto, uv, ruff, mypy |
| 04 | [AI engineering: LLMs, RAG, MCP](04-ai-engineering.md) | design a grounded, safe, provider-agnostic LLM feature and evaluate it |
| 05 | [Docker](05-docker.md) | write a multi-stage, non-root, small, scannable image; use Compose |
| 06 | [Kubernetes & Helm](06-kubernetes-helm.md) | deploy, probe, scale and secure a workload; template it with Helm |
| 07 | [GitOps with Argo CD](07-gitops-argocd.md) | explain pull-based delivery, environments and promotion |
| 08 | [Terraform](08-terraform.md) | manage state, modules, providers; build EKS/Container Apps; run the labs |
| 09 | [CI/CD & DevSecOps](09-cicd-devsecops.md) | build a pipeline with quality gates, SAST/SCA/IaC scanning, SBOM, signing, OIDC |
| 10 | [Observability](10-observability.md) | instrument with metrics/logs/traces, write PromQL and alerts, define SLOs |
| 11 | [FinOps](11-finops.md) | find waste, explain pricing models and cost governance |
| 12 | [Hands-on lab: the full scenario](12-hands-on-lab.md) | run deploy → connect → scan → strategy → fix → verify on a real account |
| 13 | [Interview preparation](13-interview-prep.md) | pitch the project, answer ~80 questions, handle system-design rounds |
| 14 | [Cheat sheet](14-cheatsheet.md) | find any command in 5 seconds |

## Suggested 4-week plan (1–2 h/day)
- **Week 1: foundations + your code.** Ch. 01, 02, 03. Run the tests, add a rule (exercise in ch. 02).
- **Week 2: AI + containers.** Ch. 04, 05. Configure Groq, break and fix the RAG eval, build the image.
- **Week 3: platform.** Ch. 06, 07, 08. kind cluster + Helm, read the Terraform, deploy the AWS lab.
- **Week 4: delivery + interviews.** Ch. 09, 10, 11, 12, 13. Push to GitHub, watch CI, practise the pitch daily.

## The one-paragraph pitch (memorise it)
> *Cloud Copilot is a multi-cloud security and FinOps posture platform. It connects to AWS and Azure with
> read-only identities, runs 103 checks mapped to CIS and NIST across 27 services, then correlates findings into
> attack paths mapped to MITRE ATT&CK and generates a phased remediation strategy with exact score impact,
> console deep links and preventive guardrails. An LLM layer, grounded with RAG and protected by redaction and
> prompt-injection guardrails, explains the strategy, and an MCP server lets AI agents use the platform. It's
> delivered like a production service: signed multi-arch images, Helm and Argo CD GitOps, Terraform for EKS and
> Azure Container Apps, a CI pipeline with SAST, SCA, IaC scanning and a Kubernetes end-to-end test, and
> Prometheus/Grafana observability.*
