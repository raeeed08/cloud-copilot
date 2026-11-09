# Threat model (STRIDE)

**Assets:** read access to cloud configuration and billing; the findings database (a map of an organisation's
weaknesses); the LLM API key; the API keys.

**Trust boundaries:** browser ↔ API, API ↔ cloud control planes, API ↔ LLM provider, MCP client ↔ MCP server,
CI ↔ cloud.

| Threat | Scenario | Mitigation |
|---|---|---|
| **S**poofing | Caller impersonates an operator | API keys (constant-time compare), mandatory in `prod`; ingress TLS; NetworkPolicy |
| **S**poofing | CI or pods use stolen static cloud keys | No static keys: GitHub OIDC, IRSA, Workload Identity, managed identity; trust policies pinned to repo/branch and service account |
| **T**ampering | Scanner credentials used to change infrastructure | Roles are read-only (`SecurityAudit`, `ViewOnlyAccess`, `Reader`), with an explicit deny on data-plane reads |
| **T**ampering | Supply-chain swap of the image | Immutable tags, deploy by digest, cosign keyless signature, SBOM + SLSA provenance, Trivy gate |
| **R**epudiation | Who suppressed a critical finding? | Suppressions store reason, principal and timestamp; optional expiry; structured JSON logs with request IDs |
| **I**nformation disclosure | Findings DB leaked | Least-privilege DB credentials from Secrets Manager / Key Vault via External Secrets; private networking |
| **I**nformation disclosure | Sensitive identifiers sent to a third-party LLM | Reversible pseudonymisation (`LLM_REDACT=true`); only compact top-N findings sent; self-hosted Ollama option |
| **I**nformation disclosure | XSS in dashboard via resource names or model output | React escaping; Markdown rendered without raw HTML; strict CSP (`script-src 'self'`) |
| **D**enial of service | Scan or chat endpoints abused (cost, throttling) | Token-bucket rate limits, one concurrent scan (409), timeouts, HPA, CronJob `concurrencyPolicy: Forbid` |
| **E**levation of privilege | **Prompt injection** via attacker-controlled tags or names ("ignore previous instructions…") | Data passed in delimited blocks with explicit instructions; model has **no tools** in chat (read-only answers); MCP tools are annotated read-only except `run_scan` |
| **E**levation of privilege | Container escape | Non-root UID, read-only root FS, `drop: [ALL]`, seccomp RuntimeDefault, no service-account token unless IRSA/WI is used |

## Residual risks and next steps
- Rate limiter is per replica (in memory). Use Redis or the ingress for global limits.
- API keys are coarse-grained. Next step: OIDC (Entra ID / Cognito) with roles (viewer, operator).
- The LLM provider still sees resource names and finding text. For regulated environments, use self-hosted
  models only.
