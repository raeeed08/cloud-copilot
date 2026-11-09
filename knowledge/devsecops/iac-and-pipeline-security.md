# DevSecOps: shifting cloud security left

## Policy as code in the pipeline
- **Checkov / Trivy config / tfsec** scan Terraform, Kubernetes manifests, Helm charts and Dockerfiles in pull
  requests and fail on high-severity misconfigurations.
- **OPA / Conftest** on `terraform show -json plan.out` for organisation-specific rules (allowed regions,
  mandatory tags, no public ingress).
- **Infracost** comments the monthly cost delta of every Terraform PR.

## Pipeline hardening
- OIDC federation from GitHub Actions to AWS (`aws-actions/configure-aws-credentials` with `role-to-assume`) and
  Azure (`azure/login` with federated credentials). No cloud secrets stored in CI.
- Pin third-party actions by commit SHA, set `permissions:` to least privilege per job, enable Dependabot for
  actions, pip, npm, Docker and Terraform.
- Secret scanning (gitleaks, GitHub push protection) and SAST (CodeQL, Bandit, Semgrep).
- Dependency auditing (pip-audit, npm audit) and container scanning (Trivy, Grype) gating the release.

## Supply chain (SLSA)
- Build once, promote the same digest through environments.
- Generate an SBOM (Syft/CycloneDX), sign the image with cosign keyless (Sigstore, GitHub OIDC identity), attach
  provenance attestations.
- Verify signatures at deploy time (Kyverno / Connaisseur / Ratify).

## Continuous posture (runtime)
Shift-left catches what's in code. Drift, click-ops and legacy resources still need runtime scanning. Running
`cloud-copilot scan --fail-on CRITICAL` on a schedule (Kubernetes CronJob or GitHub Actions cron) closes the loop.
Findings are exported as CSV/Markdown or pulled by agents through the MCP server.
