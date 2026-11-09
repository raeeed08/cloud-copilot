# Cloud Copilot lab (AWS)

A disposable, near-free AWS environment with **deliberate misconfigurations**, so you can run the full Cloud
Copilot loop on a real account: **deploy → connect → scan → strategy → fix → re-scan → verify → destroy**.

| Resource | Insecure (`secure=false`) | Rule(s) | Fixed (`secure=true`) |
|---|---|---|---|
| S3 bucket | no Block Public Access, no versioning, no TLS policy, no lifecycle | S3-003/004/005/008 | all set |
| Security groups | SSH (22) and PostgreSQL (5432) open to 0.0.0.0/0 | EC2-001, EC2-002 | restricted |
| EBS volume | 1 GiB gp2, unencrypted, unattached | EBS-002, COST-001/002 | deleted |
| Elastic IP | allocated, unused | COST-003 | released |
| IAM user | console password, no MFA, direct policy | IAM-004, IAM-008 | no password, group-based |
| KMS key | rotation off | KMS-001 | rotation on |
| DynamoDB / SNS / SQS / ECR / Logs | no PITR / no encryption / mutable tags / no retention | DDB-001, MSG-001, ECR-001/002, LOGS-001 | fixed |
| CloudTrail | none | CT-001 | multi-region trail with validation |
| Account settings* | untouched | IAM-003, S3-001, EBS-001 | strict password policy, account BPA, EBS default encryption |
| EC2 instance** | public IP + SSH open + IMDSv1 + role → **attack path** | EC2-001 + EC2-005 | IMDSv2 required |

\* only when `account_level_settings=true` (default). Destroying the lab removes them.
\** only with `-var create_instance=true` (t3.micro, ~$0.01/h). No SSH key is attached, so nobody can log in.

It also creates the **read-only scanner identity** the app uses: a role with `SecurityAudit` + `ViewOnlyAccess`
that can only be assumed by a dedicated user with an External ID. That's the same pattern as production.

## 0. Prerequisites (once)
1. An AWS account you own (a personal or sandbox account, **not** your employer's production account).
2. Credentials for *you* to run Terraform. Easiest: AWS console → IAM → Users → create `terraform-admin` with
   `AdministratorAccess` → Security credentials → Create access key (CLI). Then:
   ```bash
   aws configure            # paste the key, region eu-west-1
   aws sts get-caller-identity   # must print your account ID
   ```
   *(Your current `~/.aws/credentials` key is invalid. Replace it this way.)*
3. A billing alarm is wise: AWS console → Billing → Budgets → create a $5 monthly budget.

## 1. Deploy the insecure lab
```bash
cd infra/terraform/lab-aws
terraform init
terraform apply                                   # add -var create_instance=true for the attack-path demo
terraform output -json connect_in_cloud_copilot   # values for the UI
terraform output -raw scanner_secret_access_key
```

## 2. Connect and scan
Dashboard → **Accounts** → AWS → **IAM role (assume role)**: paste `role_arn`, `external_id`, `regions`
(e.g. `eu-west-1`) and the base access key / secret. Click **Connect & verify**: you should see your account ID.
Then **Scan**. Open **Strategy** to see the attack paths and the phased plan; every action has an
"Open in AWS ↗" link straight to the resource.

## 3. Fix, re-scan, verify
Fix a few things by hand in the console (following the plan), **or** apply all fixes as code:
```bash
terraform apply -var secure=true
```
Re-scan: **Strategy → Fixed since last scan** lists what was resolved and the score goes up.

## 4. Clean up
```bash
terraform destroy            # same -var flags you used for apply
```
Then delete the `terraform-admin` access key if you no longer need it.
