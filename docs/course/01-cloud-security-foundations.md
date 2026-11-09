# 01: Cloud security foundations

## Why it matters
Nearly every public cloud breach (Capital One 2019, countless open S3 buckets and Elasticsearch clusters) is a
**customer misconfiguration**, not a provider failure. Finding and fixing those misconfigurations
continuously is a whole product category: **CSPM (Cloud Security Posture Management)**. Wiz, Prisma Cloud,
Microsoft Defender for Cloud and AWS Security Hub all do it. Cloud Copilot is a small CSPM.

## 1. The shared responsibility model
- **Provider:** physical security, hypervisor, the managed service internals ("security *of* the cloud").
- **You:** identities, permissions, network exposure, data protection settings, logging, patching your
  workloads ("security *in* the cloud").
- The line moves with the service type: IaaS (EC2/VM) leaves more to you than PaaS (RDS/Azure SQL) or SaaS.

## 2. Identity is the new perimeter
| Concept | AWS | Azure |
|---|---|---|
| Directory / humans | IAM users (legacy), **IAM Identity Center** (SSO) | **Entra ID** users & groups |
| Workload identity | IAM **roles** (instance profile, IRSA, Pod Identity, Lambda role) | **Managed identity**, workload identity |
| Permission document | IAM policy (JSON: Effect, Action, Resource, Condition) | Role definition + role assignment (RBAC) at a scope |
| Org-wide guardrail | **SCP** (Service Control Policy) | **Azure Policy** (Deny / Audit / DeployIfNotExists) |
| Short-lived creds | STS `AssumeRole` | OAuth tokens from Entra ID |

Key principles:
- **Least privilege:** grant only what's needed (rules `IAM-009`, `IAM-008`).
- **No long-lived keys:** keys leak through repos, laptops and CI logs. Prefer roles and federation (`IAM-005`, `IAM-006`).
- **MFA everywhere humans log in** (`IAM-001`, `IAM-004`).
- **Root / Global Admin** is break-glass only (`IAM-002`).

**How an IAM decision works (AWS):** an explicit *Deny* anywhere wins → otherwise you need an *Allow* in an
identity or resource policy → SCPs and permission boundaries cap the maximum. Interviewers love this question.

**External ID**: when a third party (like Cloud Copilot) assumes a role in your account, the trust policy
requires a secret `sts:ExternalId`. This prevents the **confused deputy** problem: another customer of the
same vendor can't trick the vendor into assuming *your* role. See `infra/terraform/lab-aws/main.tf`.

## 3. Network exposure
- **Security group (AWS)**: stateful, allow-only, attached to ENIs. **NACL**: stateless, subnet-level,
  allow + deny.
- **NSG (Azure)**: stateful rules with priority, allow + deny, attached to NIC or subnet.
- `0.0.0.0/0` / `::/0` / `Internet` / `*` = the whole internet. On admin ports (22 SSH, 3389 RDP, 5985/6 WinRM)
  that's brute force within minutes (`EC2-001`, `AZ-NSG-001`). On data ports (5432, 3306, 6379, 9200, 27017) it's a
  data breach (`EC2-002`).
- Alternatives to bastions: **SSM Session Manager**, EC2 Instance Connect Endpoint, **Azure Bastion**, JIT access.
- **IMDSv1 vs IMDSv2**: the instance metadata service at `169.254.169.254` hands out the instance role's
  credentials. v1 answers any GET, so an **SSRF** bug can steal credentials (the Capital One breach). v2 requires a
  session token obtained with a PUT, which SSRF usually can't do (`EC2-005`).

## 4. Data protection
- **Encryption at rest:** S3 SSE-S3 (default since 2023) vs **SSE-KMS** (key policy = second access-control layer,
  CloudTrail audit of every decrypt). EBS/RDS encryption can't be enabled in place: snapshot → copy encrypted →
  restore (`RDS-002`, `EBS-002`).
- **KMS key rotation** (`KMS-001`), envelope encryption (data key encrypted by a KMS key).
- **In transit:** TLS 1.2+ (`AZ-STOR-003`, `ELB-002`), deny `aws:SecureTransport=false` (`S3-004`).
- **Public exposure:** S3 Block Public Access at account and bucket level (`S3-001/002/003`), public snapshots
  (`EBS-003`, `RDS-003`), Azure anonymous blob access (`AZ-STOR-001`).
- **Backups & resilience:** versioning, PITR, retention, deletion protection (`S3-005`, `DDB-001`, `RDS-004`).

## 5. Logging & detection
- **AWS:** CloudTrail (API audit log; multi-region, log-file validation, KMS, CloudWatch integration
  `CT-001…005`), **GuardDuty** (threat detection), **AWS Config** (configuration history), **Security Hub**
  (aggregation + FSBP standard), VPC Flow Logs (`VPC-001`).
- **Azure:** Activity Log + diagnostic settings → Log Analytics (`AZ-MON-001`), activity log alerts
  (`AZ-MON-002`), **Defender for Cloud** plans (`AZ-DEF-001`), Microsoft Sentinel (SIEM).
- Attackers disable logging first (MITRE T1562.008), so protect it with SCPs.

## 6. Frameworks you must be able to name
- **CIS Foundations Benchmarks** (AWS v3.0, Azure v2.0): prescriptive configuration checks. The project maps rules
  to them (`compliance` field of each rule).
- **NIST SP 800-53**: control catalogue (AC access control, AU audit, SC system & comms protection, IA identity…).
- **ISO 27001, SOC 2, PCI DSS, GDPR**: what auditors ask for; CSPM provides the evidence.
- **MITRE ATT&CK**: catalogue of attacker *techniques* (T1190 exploit public-facing app, T1110 brute force,
  T1552.005 cloud instance metadata API, T1078.004 valid cloud accounts, T1530 data from cloud storage). The
  attack-path engine labels each step with one.

## 7. From findings to risk: attack paths
A single finding is a weakness. A **chain** is a breach. "SSH open" on an unused group is HIGH; "SSH open + public
IP + IMDSv1 + instance role" is CRITICAL, because the attacker can go from the internet to AWS API access.
This is called *toxic combinations* or *attack-path analysis* (what Wiz is famous for). In the project:
`src/cloud_copilot/core/correlation.py`. Prioritise by **breaking chains at the cheapest link**.

## Where this lives in the project
- Rules: `src/cloud_copilot/providers/aws/rules/*.py`, `providers/azure/rules.py`, catalogue in `docs/rules.md`.
- Attack paths: `core/correlation.py`. Strategy & guardrails: `core/strategy.py`.
- Playbooks used by the AI: `knowledge/` (incident response, hardening, FinOps, compliance).

## Interview questions
1. **Explain the shared responsibility model with an example.** RDS: AWS patches the database engine host and
   storage; you choose whether it's public, encrypted, backed up and who can log in.
2. **How does AWS evaluate a request?** Explicit deny > SCP/permission boundary limits > any allow in identity or
   resource policy > implicit deny.
3. **Why are long-lived access keys bad, and what do you use instead?** They don't expire and leak easily; use
   roles via STS (instance profile, IRSA, OIDC federation for CI, Identity Center for humans).
4. **What is IMDSv2 and why does it matter?** Session-token-protected metadata; defeats SSRF credential theft.
5. **Security group vs NACL?** Stateful/allow-only/ENI vs stateless/allow+deny/subnet.
6. **How do you prevent a public S3 bucket organization-wide?** Account-level Block Public Access + an SCP denying
   changes to it + CI policy checks on Terraform.
7. **What is the confused deputy problem?** A trusted service tricked into acting for the wrong party; mitigated by
   ExternalId / `aws:SourceArn` / `aws:SourceAccount` conditions.
8. **CSPM vs CWPP vs CNAPP?** Posture of cloud configuration vs workload runtime protection vs the umbrella of both.
9. **What would you do first in a new AWS account?** Root MFA, no root keys, Organizations + SCPs, Identity
   Center, org CloudTrail, GuardDuty + Security Hub + Config in all regions, account BPA, EBS default encryption,
   budget alarm.

## Exercises
1. Open `providers/aws/rules/compute.py` and explain why `exposed_ports` checks each permission separately (hint:
   test `test_ssh_open_to_private_range_and_https_world_is_not_flagged`).
2. Find the MITRE technique for each step of the "Database exposed" path in `correlation.py` and look them up on
   attack.mitre.org.
3. Write down which CIS AWS controls your own account would fail today. Verify with the lab in chapter 12.
