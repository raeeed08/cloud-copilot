# Security policy

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security → Advisories → Report a vulnerability) rather
than a public issue. You will get an acknowledgement within 72 hours.

## Security model (summary)
- **Read-only by design.** Scanners use read-only credentials (`SecurityAudit` + `ViewOnlyAccess` on AWS with an
  explicit deny on data-plane reads; `Reader`/`Security Reader`/`Cost Management Reader` on Azure). No code path
  writes to a cloud account.
- **No long-lived cloud keys.** IRSA / Workload Identity in Kubernetes, managed identity on Container Apps, GitHub
  OIDC in CI.
- **API** requires API keys outside dev (startup fails if `ENVIRONMENT=prod` without `API_KEYS`), compares them in
  constant time, rate-limits scan and chat endpoints, and sets strict security headers (CSP, nosniff, frame deny).
- **LLM safety.** Untrusted cloud data is passed to the model as delimited data with explicit instructions not to
  follow embedded instructions. Account IDs, ARNs, IPs, emails and access-key IDs are pseudonymised before leaving
  the platform and restored afterwards. Model output is rendered as Markdown without raw HTML (no XSS).
- **Supply chain.** Pinned lockfiles, Dependabot, pip-audit/npm audit, Trivy, CodeQL, gitleaks; images are signed
  with cosign (keyless) and ship SBOM + SLSA provenance attestations.
- **Runtime hardening.** Non-root UID 10001, read-only root filesystem, all capabilities dropped, seccomp
  RuntimeDefault, NetworkPolicy restricting egress to DNS/443/5432.

See [docs/threat-model.md](docs/threat-model.md) for the STRIDE analysis.
