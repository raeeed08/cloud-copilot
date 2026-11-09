# 09: CI/CD & DevSecOps

## GitHub Actions vocabulary
**Workflow** (`.github/workflows/*.yml`) → triggered by **events** (`push`, `pull_request`, `schedule`,
`workflow_dispatch`) → **jobs** (run in parallel unless `needs:`) → **steps** (`uses:` an action or `run:` a
shell). `permissions:` scopes the `GITHUB_TOKEN` (least privilege per job). `concurrency:` cancels outdated runs.
Caching (`setup-uv enable-cache`, `cache: npm`, `cache-from: type=gha` for Docker layers).

## Our pipelines
### `ci.yml` (every PR and push to main)
| Job | Gates |
|---|---|
| `python` | ruff lint + format check, mypy, pytest with coverage ≥ 75%, JUnit + coverage artifacts |
| `web` | npm ci, eslint, TypeScript build |
| `security` | **Bandit** (SAST), **pip-audit** & **npm audit** (SCA: known CVEs in deps), **gitleaks** (secrets in history), **Trivy fs** (vulns, secrets, misconfig) → SARIF to GitHub code scanning |
| `iac` | `terraform fmt -check` + `validate` (all stacks incl. labs), **tflint**, **helm lint**, **kubeconform** on rendered manifests, **Checkov** (Terraform, Helm, Dockerfile, Actions) |
| `container` | Buildx image build with GHA cache → **Trivy image** gate (fixable HIGH/CRITICAL fail) → **kind** cluster → `helm install` demo profile → `helm test` → **end-to-end API checks** (scan succeeded, compliance, chat) |

### `release.yml` (push to main / tags `v*`)
1. Multi-arch build (amd64 + arm64 via QEMU) pushed to **GHCR** with semver/sha tags.
2. BuildKit **SBOM** + **provenance** (`mode=max`), plus a CycloneDX SBOM via Syft (`anchore/sbom-action`).
3. **cosign keyless signing**: GitHub's OIDC identity is the signer (Sigstore Fulcio cert + Rekor transparency
   log), no key to manage. `cosign attest` attaches the SBOM.
4. `actions/attest-build-provenance` (**SLSA** provenance).
5. Trivy scan of the pushed digest → SARIF.
6. On tags: package the Helm chart and push it to GHCR as an **OCI artifact**.
7. On main: **GitOps promotion**: commit the new digest to `deploy/environments/staging.yaml`.

### `codeql.yml`
Semantic SAST for Python, TypeScript and the workflows themselves (security-extended queries), weekly + on PRs.

### `posture-scan.yml`
Nightly `cloud-copilot scan --fail-on CRITICAL` against a real account using **OIDC → read-only role**; report in
the job summary. *Continuous compliance as code.*

### `dependabot.yml`
Weekly grouped updates for uv, npm, Docker base images, Actions, Terraform providers.

## DevSecOps concepts to master
- **Shift left**: find issues at PR time (cheap) rather than in prod (expensive). Also **shift right**: runtime
  posture (this product), because drift and click-ops bypass CI.
- **SAST** (source analysis: Bandit, CodeQL, Semgrep) vs **DAST** (attack the running app: ZAP) vs **SCA**
  (dependency CVEs: pip-audit, npm audit, Trivy, Dependabot) vs **IaC scanning** (Checkov, tfsec/Trivy config,
  tflint) vs **secret scanning** (gitleaks, push protection) vs **container scanning** (Trivy, Grype).
- **SBOM**: the ingredient list of an artifact (CycloneDX/SPDX), needed to answer "are we affected by CVE-X?".
- **SLSA**: supply-chain framework; provenance attests *how/where* an artifact was built.
- **Signing & verification**: cosign signs; Kyverno/Connaisseur verify at admission so unsigned images can't run.
- **OIDC federation**: CI gets short-lived cloud credentials; no long-lived secrets in GitHub.
- **Pin actions**: by full commit SHA for third-party actions (Dependabot keeps them fresh). Tags can be moved
  (tj-actions/changed-files incident, 2025).
- **Branch protection**: required checks, reviews, signed commits, no force-push on main.

## Commands
```bash
gh run list                    gh run watch                 gh run view --log-failed
gh pr create --fill            gh pr checks
cosign verify ghcr.io/<owner>/cloud-copilot@sha256:… \
  --certificate-identity-regexp 'https://github.com/<owner>/cloud-copilot/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/<owner>/cloud-copilot:edge --format '{{ json .SBOM }}'
trivy image --severity HIGH,CRITICAL --ignore-unfixed cloud-copilot:local
checkov -d infra/terraform     gitleaks detect --source .
```

## Interview questions
1. **Describe your CI/CD pipeline.** Use the tables above: gates by stage, artifacts, promotion by digest, GitOps.
2. **SAST vs DAST vs SCA?** Code vs running app vs dependencies.
3. **How do you avoid storing cloud credentials in CI?** OIDC federation with tightly scoped trust (repo + branch
   or environment).
4. **What is an SBOM and why sign images?** Inventory for vulnerability response; signatures prove origin and
   integrity, enforceable at deploy time.
5. **A dependency has a critical CVE on Friday evening: what do you do?** Assess exploitability/reachability,
   check the SBOM for affected services, patch/bump via Dependabot PR, rebuild, roll out via GitOps, or mitigate
   (WAF, config) and document the risk acceptance with expiry (like our suppressions).
6. **How do you make pipelines fast?** Caching (deps, Docker layers), parallel jobs, test splitting, only build
   what changed, small images.

## Exercises
1. Push the branch, open a PR, and read every job's log. Make one test fail on purpose and see the gate block.
2. Add `semgrep ci --config p/python` as a job.
3. Add a Kyverno policy (`verifyImages`) that only admits images signed by your repo's workflow.
