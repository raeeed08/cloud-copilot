# Azure subscription security baseline

## Identity (Microsoft Entra ID)
- Conditional Access: require MFA for all users, block legacy authentication, require compliant devices for admins.
- Privileged Identity Management (PIM) for just-in-time Owner/Contributor; no standing Global Admins beyond
  2 break-glass accounts.
- Managed identities for workloads instead of service principal secrets; workload identity federation for CI/CD
  (GitHub OIDC → `azure/login` without secrets).
- Disable shared-key access on storage (AZ-STOR-004), local accounts on AKS (AZ-AKS-002), ACR admin user
  (AZ-ACR-001), and use Entra ID admins on SQL (AZ-SQL-004).

## Governance
- Management groups + Azure Policy initiatives (Microsoft Cloud Security Benchmark, CIS) assigned at the root
  with `Deny`/`DeployIfNotExists` effects.
- Resource locks on critical resources; tags for owner/cost-center enforced by policy.

## Detection & logging
- Subscription diagnostic setting exporting the Activity Log to Log Analytics (AZ-MON-001), with Microsoft
  Sentinel on top for correlation.
- Activity log alerts for policy assignment changes, NSG changes and SQL firewall changes (AZ-MON-002).
- Defender for Cloud: enable Standard plans for Servers, SQL, App Service, Storage, Key Vault, Containers and
  Resource Manager (AZ-DEF-001).

## Network & data
- Private endpoints for Storage, Key Vault, SQL and ACR; disable public network access where possible
  (AZ-STOR-005, AZ-KV-003, AZ-ACR-002).
- Key Vault with RBAC, soft delete and purge protection (AZ-KV-001/002).
- TLS 1.2 minimum everywhere (AZ-STOR-003, AZ-SQL-005, AZ-APP-002), HTTPS-only web apps (AZ-APP-001).
