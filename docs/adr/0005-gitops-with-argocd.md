# ADR 0005: Pull-based GitOps with Argo CD

**Status:** accepted

## Decision
CI builds, scans, signs and pushes the image, then commits the new digest to `deploy/environments/staging.yaml`.
Argo CD (ApplicationSet) auto-syncs staging. Prod is promoted by PR and synced manually.

## Consequences
- CI never holds cluster credentials, and Git history is the deployment audit log.
- Drift is detected and self-healed in staging.
