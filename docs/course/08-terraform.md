# 08: Terraform (Infrastructure as Code)

## Core concepts
- **Declarative**: you describe the end state; Terraform computes a **plan** (diff) and **applies** it.
- **Providers** (`hashicorp/aws`, `azurerm`, `azuread`, `helm`, `kubernetes`, `random`) talk to APIs. Pin them
  (`version = "~> 5.80"`); `.terraform.lock.hcl` pins exact builds + hashes (commit it for root modules).
- **Resources** (things Terraform creates) vs **data sources** (things it reads, e.g. `data.aws_vpc.default`).
- **State** maps your code to real resource IDs. It contains secrets in plain text → **remote, encrypted,
  locked** backend in teams: S3 + native lockfile (`use_lockfile = true`, Terraform ≥ 1.10) or DynamoDB lock
  (older), or Azure Storage (`infra/terraform/*/backend.hcl.example`). Never commit `terraform.tfstate` (gitignored).
- **Variables / outputs / locals**; `sensitive = true` hides values in CLI output (not in state!).
- **Modules**: reusable units (`modules/aws-scanner-role`, `modules/azure-scanner-identity`) and registry
  modules (`terraform-aws-modules/vpc`, `/eks`, `/iam`).
- **Meta-arguments**: `count` (the labs toggle resources with `count = var.secure ? 1 : 0`), `for_each`
  (`azurerm_role_assignment` per role), `depends_on`, `lifecycle { ignore_changes, prevent_destroy }`.

## The stacks in this repo
| Path | What it builds | Things to talk about |
|---|---|---|
| `modules/aws-scanner-role` | read-only IAM role, trust for IRSA and/or principals with ExternalId, explicit deny on data reads | least privilege, confused deputy, dynamic blocks |
| `modules/azure-scanner-identity` | user-assigned managed identity + Reader/Security Reader/Cost Management Reader + optional AKS federated credential | RBAC scopes, `setproduct`, workload identity |
| `aws/` | VPC (3 AZ, NAT, flow logs) · EKS 1.31 (private endpoint, audit logs, KMS secrets, IRSA, Graviton nodes, IMDSv2) · ECR (immutable, scan on push, lifecycle) · GitHub OIDC deploy role · Secrets Manager · Argo CD + External Secrets via Helm | each setting references the rule it satisfies (EKS-001/002/003, ECR-001/002, EC2-005, VPC-001): "we eat our own dog food" |
| `azure/` | Resource group, Log Analytics, ACR (no admin), Key Vault (RBAC, purge protection), Container Apps with managed identity and Key Vault secret references | serverless containers, secretless config |
| `lab-aws/`, `lab-azure/` | deliberately insecure resources + scanner identity, `secure` toggle | the hands-on loop (chapter 12) |

## GitHub OIDC → AWS (no stored cloud keys in CI)
`aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com` + a role whose trust policy checks
`aud = sts.amazonaws.com` and `sub = repo:<owner>/<repo>:ref:refs/heads/main`. The workflow uses
`aws-actions/configure-aws-credentials` with `role-to-assume`; GitHub issues a short-lived OIDC token per run.

## Workflow
```bash
terraform fmt -recursive          # style
terraform init                    # download providers/modules, configure backend
terraform validate                # syntax + types
terraform plan -out tf.plan       # review the diff (CI posts it on the PR)
terraform apply tf.plan
terraform output -json            # read outputs
terraform state list | show       # inspect state
terraform import <addr> <id>      # adopt an existing resource (or `import {}` blocks)
terraform destroy
```
Team practices: plan in CI on every PR, apply on merge (or via Atlantis/Terraform Cloud/Spacelift), policy as
code on the plan (Checkov, tflint, OPA/Conftest), drift detection with scheduled `plan`, Infracost for cost diffs.

## Pitfalls
- Secrets in state (`random_password`, access keys in the labs) → protect the backend, prefer generating
  secrets outside Terraform in production.
- `count` index shifting when list order changes → prefer `for_each` with stable keys.
- Provider major upgrades break schemas (we hit azurerm 5.x renaming arguments; fixed by pinning `< 5.0`).
- Big-bang monolith states → split by lifecycle/team (network, cluster, apps) and pass outputs.

## Interview questions
1. **What is Terraform state and how do you secure it?** The mapping code↔resources; remote encrypted backend with
   locking, restricted IAM, versioning; no local state in teams.
2. **How do you handle multiple environments?** Separate state per env (directories or workspaces) + per-env
   tfvars; same modules.
3. **`count` vs `for_each`?** Index-based vs key-based identity; `for_each` avoids accidental destroy/recreate.
4. **How do you prevent dangerous changes?** Plan review, policy checks, `prevent_destroy`, least-privilege apply
   role, protected branches.
5. **Terraform vs CloudFormation/Bicep vs Pulumi?** Multi-cloud HCL with big ecosystem vs native single-cloud vs
   general-purpose languages.
6. **What is drift and how do you detect it?** Real infra differs from code; scheduled `terraform plan`, AWS
   Config, or a CSPM like this project.

## Exercises
1. `cd infra/terraform/lab-aws && terraform init && terraform plan`: read the plan and map 5 resources to rule IDs.
2. Change the lab's SSH rule to use `for_each` over a map of ports.
3. Write a Conftest/OPA policy that rejects any `aws_security_group` ingress from `0.0.0.0/0` on port 22 and run it
   on `terraform show -json plan`.
