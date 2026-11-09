# 06: Kubernetes & Helm

## Kubernetes in one page
- **Control plane** (API server, etcd, scheduler, controllers) keeps **actual state** converging to **desired
  state** you declare in YAML. **Nodes** run pods via the kubelet.
- **Pod**: smallest unit, one or more containers sharing network/volumes. Ephemeral.
- **Deployment** → ReplicaSet → Pods: rolling updates, rollbacks. **Service**: stable virtual IP/DNS in front of
  pods (selector on labels). **Ingress**: HTTP routing + TLS from outside.
- **ConfigMap / Secret**: configuration and sensitive values (Secrets are only base64 → encrypt etcd, use
  External Secrets).
- **Job / CronJob**: run-to-completion work (our scheduled scans).
- **Namespace**: isolation & quota boundary. **ServiceAccount**: pod identity (→ IRSA / Workload Identity).

## What our chart deploys (`deploy/helm/cloud-copilot/templates/`)
| Object | Why it's there |
|---|---|
| `Deployment` (api) | 2+ replicas, rolling update `maxUnavailable: 0`, **probes**, resource requests/limits, hardened `securityContext`, topology spread across zones, config checksum annotation (restart on config change) |
| `Service` + optional `Ingress` | stable endpoint; TLS via cert-manager annotation |
| `HPA` | scale on CPU 2→6 replicas; scale-down stabilisation to avoid flapping |
| `PodDisruptionBudget` | keep ≥1 pod during node drains/upgrades |
| `CronJob` (scan) | scheduled scan, `concurrencyPolicy: Forbid`, deadline, TTL cleanup, optional `--fail-on` |
| `Deployment` (mcp) | optional MCP endpoint for agents |
| `ConfigMap` / `Secret` / `ExternalSecret` | config; secrets created once (`SECRET_KEY` generated and kept via `lookup`) or synced from AWS Secrets Manager / Key Vault |
| `ServiceAccount` | annotations for **IRSA** (`eks.amazonaws.com/role-arn`) or **Workload Identity**; token automount only when needed |
| `NetworkPolicy` | ingress only from ingress-nginx/monitoring; egress only DNS, 443, 5432 |
| `ServiceMonitor` / `PrometheusRule` | Prometheus Operator scraping and alerts |
| `tests/test-connection.yaml` | `helm test` smoke check |

### Probes: know the difference
- **startupProbe**: gives slow starters time (migrations) before the others kick in.
- **livenessProbe** (`/healthz`): "is the process stuck?" → restart. Must not depend on the DB, or a DB outage
  restarts every pod.
- **readinessProbe** (`/readyz`, checks the DB): "can I take traffic?" → removed from the Service endpoints.

### Requests vs limits
Requests = scheduling guarantee; limits = cap. CPU over limit → throttled; memory over limit → **OOMKilled**.
We set a memory limit but no CPU limit (avoids throttling latency spikes, a common best practice).

### Pod security
`runAsNonRoot`, fixed UID, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `drop: [ALL]`,
`seccompProfile: RuntimeDefault` = the **restricted** Pod Security Standard.

## IRSA / Workload Identity (no keys in the cluster)
EKS exposes an OIDC issuer. A pod's ServiceAccount token is exchanged with STS (`AssumeRoleWithWebIdentity`) for
the IAM role whose trust policy names `system:serviceaccount:<ns>:<sa>` (`infra/terraform/modules/aws-scanner-role`).
AKS Workload Identity does the same with a federated credential on a managed identity.

## Helm
- **Chart** = templates + `values.yaml` + `Chart.yaml` (versions, dependencies such as the Bitnami PostgreSQL
  subchart). **Release** = an installed instance. **Values files per environment** (`values-demo.yaml`,
  `deploy/environments/prod.yaml`).
- Go templating: `{{ include "cc.fullname" . }}`, `{{- with }}`, `toYaml | nindent`, `lookup`, `randBytes`.
- `_helpers.tpl` holds named templates (labels, image reference by digest or tag).

## Commands
```bash
helm dependency build deploy/helm/cloud-copilot
helm lint deploy/helm/cloud-copilot --strict -f deploy/helm/cloud-copilot/values-demo.yaml
helm template t deploy/helm/cloud-copilot -f … | kubeconform -strict -summary
helm upgrade --install cc deploy/helm/cloud-copilot -n cc --create-namespace -f …values-demo.yaml --wait
helm test cc -n cc         helm history cc -n cc        helm rollback cc 1 -n cc
kubectl get pods,svc,hpa,cronjob -n cc
kubectl describe pod <pod> -n cc          # events: image pull, probe failures, OOMKilled
kubectl logs deploy/cc-cloud-copilot -n cc -f
kubectl port-forward svc/cc-cloud-copilot 8000:80 -n cc
kubectl create job --from=cronjob/cc-cloud-copilot-scan manual-scan -n cc
kubectl rollout status deploy/cc-cloud-copilot -n cc ; kubectl rollout undo …
kubectl top pods -n cc                     # needs metrics-server
make kind                                  # local cluster with the demo profile
```
*(No local helm? `docker run --rm -v $PWD:/w -w /w alpine/helm:3.16.4 lint …`.)*

## Debugging checklist (interview favourite: "a pod is in CrashLoopBackOff")
1. `kubectl describe pod`: events, exit code, last state (OOMKilled? probe failed?).
2. `kubectl logs --previous`: the crashed container's logs.
3. Config/secret missing? Env vars? Image tag right? `ImagePullBackOff` = registry auth or wrong tag.
4. Probe too aggressive? Startup probe missing?
5. `kubectl exec` / ephemeral debug container to test DNS and network (`nslookup`, `curl`).

## Interview questions
1. **Deployment vs StatefulSet vs DaemonSet?** Stateless replicas / stable identity + storage per pod / one pod
   per node.
2. **Liveness vs readiness?** Restart vs remove from load balancing.
3. **How does a Service find pods?** Label selector → EndpointSlices → kube-proxy/iptables or eBPF.
4. **How do pods get cloud permissions without keys?** IRSA / EKS Pod Identity / AKS Workload Identity.
5. **How do you do zero-downtime deploys?** Rolling update with `maxUnavailable: 0`, readiness probes, PDBs,
   graceful shutdown, backward-compatible DB migrations.
6. **What does HPA need?** metrics-server (or custom metrics adapter), resource requests set.
7. **Why are Kubernetes Secrets not secure by default?** Base64 only; need etcd encryption (KMS), RBAC, External
   Secrets / CSI driver.

## Exercises
1. Deploy with `make kind`, kill a pod and watch the Deployment replace it.
2. Set the memory limit to `64Mi`, redeploy, and explain the `OOMKilled` you get.
3. Render the chart with `deploy/environments/prod.yaml` and find the IRSA annotation and the NetworkPolicy.
