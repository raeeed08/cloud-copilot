# Kubernetes hardening (EKS and AKS)

## Control plane
- Private API endpoint, or a public endpoint restricted to known CIDRs (EKS-001, AZ-AKS-001).
- Control-plane audit logs on: EKS `api`, `audit`, `authenticator` (EKS-002); AKS diagnostic settings for
  `kube-audit-admin`.
- Envelope-encrypt Secrets with KMS / Key Vault (EKS-003). Better still, keep secrets out of etcd with External
  Secrets Operator or the Secrets Store CSI driver.
- Keep versions inside the provider's standard support window. Extended support on EKS costs 6× more per
  cluster-hour.

## Identity
- EKS: access entries + IAM Identity Center; IRSA or EKS Pod Identity for pods. Never reuse node role
  permissions.
- AKS: Entra ID integration with Azure RBAC, `disableLocalAccounts=true` (AZ-AKS-002), Workload Identity.

## Workloads
- Pod Security Admission `restricted` profile on application namespaces; Kyverno or Gatekeeper to enforce
  non-root, read-only root filesystem, dropped capabilities, no privileged/hostPath.
- NetworkPolicies with default-deny per namespace (AZ-AKS-003 checks that a policy engine exists).
- Image supply chain: scan on push (ECR-001), immutable tags (ECR-002), sign images (cosign) and verify signatures
  at admission (Kyverno `verifyImages`), and generate SBOMs (syft).
- Requests/limits, PodDisruptionBudgets and HPA for resilience; runtime detection with Falco or GuardDuty
  Runtime Monitoring / Defender for Containers.
