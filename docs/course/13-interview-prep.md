# 13: Interview preparation

## A. Pitching the project
**30 seconds**: use the one-paragraph pitch in [the course README](README.md).

**2 minutes (structure: problem → solution → how → impact → what I learned)**
1. *Problem*: cloud breaches come from misconfiguration; tools produce hundreds of findings with no order.
2. *Solution*: read-only scanning of AWS/Azure, 103 checks, correlation into attack paths, a phased strategy with
   score impact and console links, verification by re-scan, guardrails to prevent recurrence.
3. *How*: FastAPI + rule registry; attack-path engine; LLM gateway with RAG, redaction and fallbacks; MCP server;
   Postgres; React. Delivered with Docker, Helm, Argo CD, Terraform (EKS, Container Apps), GitHub Actions with
   security gates, signed images, Prometheus/Grafana.
4. *Impact on the demo/lab*: score from 30 to ~90+ after following the plan; every fix verified by re-scan.
5. *Learned*: separating deterministic decisions from LLM narration; least-privilege identity design; making a
   system degrade gracefully.

**STAR stories you can tell (true, from building this)**
- *The misleading AI status*: S: the dashboard said "Connected" while the key was rejected. T: make status
  truthful. A: tracked real health from the last call and a test endpoint, stopped retrying all models on
  401/403. R: users see "failing: key rejected" immediately. Lesson: report observed state, not configured state.
- *The CSP that broke Swagger*: a strict Content-Security-Policy blocked the API docs. Fixed with a per-route
  policy instead of loosening it globally. Lesson: security controls need scoping, not removal.
- *Encryption key consistency*: per-pod generated keys would make credentials undecryptable across replicas.
  Fixed with a shared `SECRET_KEY` (Helm generates it once, keeps it with `lookup`; prod refuses to start
  without it).
- *Schema migration on live data*: adding NOT NULL JSON columns to a table with rows needs a server default;
  migrations run under a Postgres advisory lock so replicas don't race.
- *Provider breaking change*: azurerm 5.x renamed arguments; pinned `< 5.0` and validated every stack in CI.

## B. Technical questions with model answers

### Cloud & security
1. **Shared responsibility?** Provider secures the cloud; you secure what you put in it (identity, config, data, network).
2. **How does IAM policy evaluation work?** Explicit deny wins; SCPs/boundaries cap; need an allow; default deny.
3. **Role vs user?** Roles give temporary credentials via STS to whoever is trusted; users have long-lived
   credentials. Prefer roles.
4. **What is IRSA?** IAM roles for Kubernetes service accounts via the EKS OIDC issuer and AssumeRoleWithWebIdentity.
5. **Explain IMDSv2.** Session token via PUT protects instance credentials from SSRF.
6. **Security groups vs NACLs?** Stateful allow-only on ENIs vs stateless allow/deny on subnets.
7. **How to give a vendor access to your account?** Cross-account role, read-only, ExternalId, least privilege,
   monitored with CloudTrail.
8. **What is a CSPM? CNAPP?** Config posture scanning; CNAPP = CSPM + workload protection + CIEM + IaC scanning.
9. **What's an attack path?** A chain of weaknesses (exposure → access → privilege → data) an attacker can
   combine; fix the cheapest link.
10. **How do you secure an S3 bucket?** Account + bucket BPA, no public policy/ACL, TLS-only policy, SSE-KMS,
    versioning (+Object Lock for logs), access logging/data events, least-privilege bucket policy.
11. **First 5 things you'd check in an unknown AWS account?** Root MFA/keys, public exposure (SG 0.0.0.0/0, public
    buckets/snapshots/DBs), admin users without MFA, CloudTrail/GuardDuty coverage, old access keys.
12. **What do CIS, NIST and MITRE ATT&CK each give you?** Configuration benchmarks; a control catalogue; attacker
    techniques for threat modelling and detection.
13. **Incident: leaked access key: steps?** Deactivate key, deny-all, revoke sessions, investigate CloudTrail
    across regions, remove persistence, rotate secrets, post-mortem, prevent (roles, secret scanning).

### Containers & Kubernetes
14. **Multi-stage build benefits?** Smaller image, no build tools in runtime, fewer CVEs, cacheable layers.
15. **How do you harden a container?** Non-root, read-only FS, drop capabilities, no-new-privileges, seccomp,
    minimal base, scanned, signed.
16. **Liveness vs readiness vs startup probes?** Restart vs traffic gating vs slow-start grace.
17. **CrashLoopBackOff troubleshooting?** describe → events/exit code → logs --previous → config/secrets → probes
    → resources (OOMKilled).
18. **Requests vs limits?** Scheduling guarantee vs hard cap; memory over limit = OOMKill; CPU = throttling.
19. **How does HPA work?** Controller compares metric (CPU %) to target using requests; scales replicas within
    min/max with stabilisation.
20. **What is a PDB?** Limits voluntary disruptions (drains) so a minimum stays available.
21. **NetworkPolicy default?** All traffic allowed until a policy selects the pod; then only what's allowed.
22. **Helm vs Kustomize?** Templating + packaging/releases vs overlay patching of plain YAML.
23. **How do you manage secrets in Kubernetes?** External Secrets (from Secrets Manager/Key Vault), etcd
    encryption, RBAC, never in Git.

### GitOps, CI/CD, DevSecOps
24. **GitOps?** Desired state in Git, pulled and reconciled by an in-cluster agent; audit and rollback via Git.
25. **Promotion strategy?** Build once, promote the same digest; automated staging, gated prod.
26. **Deployment strategies?** Rolling, blue/green, canary (Argo Rollouts/Flagger), feature flags.
27. **SAST/DAST/SCA/IaC scanning: examples?** Bandit/CodeQL; ZAP; pip-audit/Trivy; Checkov/tflint.
28. **What's an SBOM and SLSA?** Component inventory; build-integrity framework with provenance.
29. **Keyless signing?** cosign + Sigstore: OIDC identity → short-lived cert, logged in Rekor; verify by identity.
30. **No secrets in CI: how?** OIDC federation to AWS/Azure with branch/environment-scoped trust.
31. **Pipeline is slow, what do you do?** Cache, parallelise, split tests, build only changed parts, smaller images.

### Terraform
32. **What is state? Remote backend?** Mapping to real resources; S3/Azure Storage with encryption + locking.
33. **count vs for_each?** Index vs stable key identity.
34. **Modules: when?** Reusable, versioned building blocks with clear inputs/outputs.
35. **Drift?** Real ≠ code; detect with scheduled plan/Config/CSPM; reconcile via code.
36. **How do you review infra changes?** PR with plan output, policy checks (Checkov/OPA), Infracost, approvals.
37. **Importing existing resources?** `import` blocks/command, then align code until plan is empty.

### Python / backend
38. **Why FastAPI?** Types → validation + OpenAPI; DI; performance; async when useful.
39. **Blocking code in async handlers?** Freezes the event loop; use sync handlers/thread pool.
40. **How do you test AWS code?** Pure logic + moto/Stubber for I/O; no real accounts in CI.
41. **DB migrations in production?** Versioned (Alembic), backward compatible, locked, run once per release.
42. **Idempotency?** Same request twice = same result; important for retries and workers.
43. **Why 202 for scans?** Long-running work runs async; the client polls the status resource.

### AI engineering
44. **RAG vs fine-tuning?** Fresh, citable knowledge at query time vs changing model behaviour.
45. **Chunking strategy?** By semantic sections with size limits and stable IDs; test retrieval quality.
46. **Hybrid search?** BM25 + embeddings fused with RRF.
47. **How do you evaluate RAG?** Golden questions → recall@k/MRR; faithfulness checks; regression in CI.
48. **Prompt injection defence?** Least privilege, no side-effecting tools on untrusted data, delimiting,
    output encoding, human approval.
49. **Hallucinations: mitigation?** Grounding with retrieved data, "say you don't know", deterministic logic for
    decisions, citations, low temperature.
50. **LLM reliability in production?** Timeouts, retries, fallbacks, health metrics, deterministic fallback, cost limits.
51. **What is MCP?** Standard protocol for AI clients to use tools/resources/prompts; JSON-RPC over stdio/HTTP.
52. **Privacy with third-party LLMs?** Minimise, pseudonymise, self-host for sensitive data, zero-retention terms.

### Observability & FinOps
53. **Metrics/logs/traces?** Aggregates / events / request flows.
54. **SLO & error budget?** Target reliability; budget of allowed failures governs release pace.
55. **High-cardinality labels?** Avoid unbounded label values.
56. **Good alert?** Actionable, symptom-based, with runbook, low noise, `for:` duration.
57. **Reduce the bill 30%?** Visibility, waste cleanup, right-sizing, commitments, Spot, architecture, governance.
58. **Hidden cloud costs?** NAT/data transfer, logs ingestion, idle IPs, snapshots, extended support.

## C. System design round: "Design a CSPM for 1,000 AWS accounts"
Use your project as the backbone and scale it:
1. **Access**: AWS Organizations; a read-only role deployed to every account via CloudFormation StackSets /
   Terraform; central scanner assumes it with ExternalId.
2. **Scheduling**: EventBridge/K8s CronJob enqueues one message per account+region (SQS); workers (K8s Jobs with
   KEDA autoscaling on queue depth) scan; respect API rate limits (adaptive retries, per-account concurrency).
3. **Event-driven freshness**: CloudTrail/EventBridge events (`AuthorizeSecurityGroupIngress`, `PutBucketPolicy`)
   trigger targeted rescans → near-real-time.
4. **Storage**: findings in Postgres (current state) + object storage/warehouse for history; inventory graph
   (resources + relationships) for attack paths (graph DB or relational with edges).
5. **Rules**: versioned registry (as here) or OPA/Rego; per-tenant suppressions and custom rules.
6. **Correlation**: graph traversal (internet → compute → identity → data).
7. **Outputs**: dashboard, API, ticketing (Jira) integration, Slack alerts, MCP for agents, Security Hub/ASFF export.
8. **Security**: tenant isolation, encryption (KMS per tenant), least privilege, audit logs.
9. **Observability & cost**: per-account scan duration, error rates; Spot workers.
Mention trade-offs: polling vs events, freshness vs API cost, false positives (suppressions), multi-cloud
abstraction cost.

## D. Questions to ask the interviewer
- How do teams here detect and fix cloud misconfigurations today: CI, runtime, or both?
- What does the path to production look like (GitOps? approvals?), and how long does it take?
- How is on-call organised, and what are your SLOs?
- What would success look like for an intern in the first 3 months?

## E. Daily drill (15 minutes)
1. Say the 30-second pitch out loud.
2. Answer 5 random questions above without looking.
3. Explain one file of the repo to an imaginary colleague.
4. Run one command from the cheat sheet you haven't used yet.
