# 07: GitOps with Argo CD

## Principles (OpenGitOps)
1. **Declarative**: the desired state is described (Helm chart + values), not scripted.
2. **Versioned & immutable**: it lives in Git; every change is a commit (audit log, review, revert).
3. **Pulled automatically**: an agent *in the cluster* pulls the state. CI never needs cluster credentials.
4. **Continuously reconciled**: drift (someone `kubectl edit`s) is detected and corrected.

**Push-based** (CI runs `helm upgrade` with cluster admin creds) vs **pull-based** (Argo CD/Flux in the cluster):
pull reduces the attack surface of CI and gives drift detection.

## Argo CD objects in the repo (`deploy/argocd/`)
- `AppProject` `cloud-copilot`: which repos and destinations are allowed (a security boundary).
- `ApplicationSet` with a **list generator** → one `Application` per environment:
  - `staging`: namespace `cloud-copilot-staging`, **automated sync** with `prune` + `selfHeal`.
  - `prod`: namespace `cloud-copilot`, **manual sync** (a human clicks Sync after review).
- Each Application points to `deploy/helm/cloud-copilot` with `valueFiles: ../../environments/<env>.yaml`.
- `syncOptions: CreateNamespace=true, ServerSideApply=true`, retry with backoff.

## The promotion flow
```
merge to main → release.yml builds, scans, signs image → digest D
             → bot commits `image.digest: D` into deploy/environments/staging.yaml
             → Argo CD sees the commit → syncs staging automatically
             → you validate staging → PR copying D into prod.yaml → review → merge → Sync prod
```
Rollback = `git revert` (or Argo's history). Same artifact (digest) is promoted, never rebuilt per environment.

## Sync states you'll see
- **Synced / OutOfSync**: Git vs cluster. **Healthy / Progressing / Degraded**: from resource health checks.
- **Sync waves & hooks**: order resources (e.g. migrations Job `PreSync`). We migrate at app startup under a lock
  instead. Know both options.

## Bootstrapping
Terraform installs Argo CD and External Secrets with `helm_release` (`infra/terraform/aws/main.tf`), then you
`kubectl apply -f deploy/argocd/`. "App of apps" is the pattern where one Application manages the others.

## Commands
```bash
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
kubectl -n argocd port-forward svc/argocd-server 8080:80
argocd login localhost:8080 --insecure
argocd app list                argocd app get cloud-copilot-staging
argocd app diff cloud-copilot-prod      argocd app sync cloud-copilot-prod
argocd app history cloud-copilot-prod   argocd app rollback cloud-copilot-prod <id>
```

## Interview questions
1. **What is GitOps and why use it?** Git as the single source of truth, pull-based reconciliation; auditability,
   easy rollback, no cluster creds in CI, drift correction.
2. **Argo CD vs Flux?** Both CNCF GitOps controllers; Argo has a rich UI and ApplicationSets; Flux is more
   toolkit-like and composable.
3. **How do you handle secrets in GitOps?** Never plaintext in Git: External Secrets Operator (we use it), Sealed
   Secrets, SOPS, or the CSI secret store driver.
4. **How do you promote between environments?** Same immutable artifact; change only the per-env values via PR;
   automate lower envs, gate prod.
5. **What does selfHeal do?** Reverts manual changes made directly in the cluster.

## Exercises
1. Install Argo CD in your kind cluster (`kubectl create ns argocd && kubectl apply -n argocd -f
   https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml`), apply `deploy/argocd/`
   (after pushing the repo) and watch staging sync.
2. `kubectl scale deploy … --replicas=5` on staging and watch selfHeal revert it.
