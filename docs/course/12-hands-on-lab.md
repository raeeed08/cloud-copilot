# 12: Hands-on lab: the full scenario on a real account

Goal: experience the whole product loop like a cloud security engineer would on day one in a new company, and be
able to **demo it live in an interview** (screen-share the dashboard, show the console, show the code).

```
create credentials → deploy lab → configure AI → connect account → scan → read attack paths
→ follow the strategy (console + code) → re-scan → verify resolved → add guardrails → destroy
```
Time: ~1h30. Cost: a few cents (destroy at the end).

## Step 0: prepare credentials (10 min)
Your current `~/.aws/credentials` key is **invalid**, so replace it.
1. AWS console (as root, only this once) → enable **MFA on root** (that's rule IAM-001 fixed for real).
2. IAM → Users → **Create user** `terraform-admin` → attach `AdministratorAccess` → Security credentials → **Create
   access key** → "Command Line Interface".
3. On your machine:
   ```bash
   aws configure                     # key, secret, region eu-west-1, output json
   aws sts get-caller-identity       # prints your 12-digit account ID → it works
   ```
4. Billing → Budgets → create a **$5 monthly budget** with email alert (FinOps reflex).

## Step 1: start the platform (5 min)
```bash
cd ~/Desktop/cloud-copilot
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:$PWD -w $PWD -e HOME=$HOME \
  docker:27.4-cli docker compose up -d --build          # or: make dev  (no Docker)
open http://localhost:8000
```

## Step 2: configure the AI (3 min)
1. Create a free key at <https://console.groq.com/keys>.
2. Dashboard → **Settings → AI provider** → *Groq* → paste the key → **Save & test** → you must see
   "Connected: openai/gpt-oss-120b answered in … ms".
3. Ask the Copilot "hi": it should answer briefly with your posture, not dump findings.

## Step 3: deploy the vulnerable lab (10 min)
```bash
cd infra/terraform/lab-aws
terraform init
terraform plan                                   # READ IT: map resources to rule IDs (see README table)
terraform apply -var create_instance=true        # instance optional, enables the CRITICAL attack path
terraform output -json connect_in_cloud_copilot
terraform output -raw scanner_secret_access_key ; echo
```
What you just created: an insecure S3 bucket, SSH/PostgreSQL open security groups, an orphan unencrypted gp2
volume, an idle Elastic IP, an IAM user with a console password and no MFA, a KMS key without rotation,
unencrypted SNS/SQS, a DynamoDB table without PITR, a mutable ECR repo, a never-expiring log group, no
CloudTrail, plus a **read-only role** that can only be assumed with an External ID.

## Step 4: connect the account (5 min)
Dashboard → **Accounts → Connect an account → AWS → IAM role (assume role)**:
- Role ARN: `role_arn` output · External ID: `external_id` output · Regions: `eu-west-1`
- Base access key ID / secret: `access_key` output and the secret from the previous command.
Click **Connect & verify** → status *connected*, your account ID, and an **Open AWS console** button.

Think about *why* this is safer than pasting your admin key: the stored key can only call `sts:AssumeRole` on one
role, which can only read, and only with the External ID.

## Step 5: scan and read (15 min)
Pick your account in the target selector → **Run scan** (regions in parallel, ~1–2 min).
1. **Overview**: score, critical count, the AI strategy briefing.
2. **Strategy → Attack paths**: with the instance you should see *"Internet-exposed server … → cloud credential
   theft"* (public IP + SSH open + IMDSv1 + role) and *"Detection blind spot"* (no CloudTrail + GuardDuty off).
   Click the MITRE IDs and read what attackers do.
3. **Strategy → phases**: open an action: why, how, effort, score gain, the resources and **Open in AWS ↗**.
4. **Findings**: filter CRITICAL; open the drawer; **Ask Copilot** "how do I fix this step by step?".
5. **Compliance**: which CIS 3.0 controls fail.
6. **Inventory**: per-service status. Some services may show *partial* (regions not enabled, or the scanner role
   lacking a permission): explain why that's a feature (fault isolation).

## Step 6: fix like an engineer (20 min)
Do **two fixes by hand in the console** (that's what the strategy links are for):
- Today phase → `EC2-001`: Open in AWS → edit inbound rules → change source to your IP/32 or delete the rule.
- `EC2-005`: instance → Actions → Instance settings → **Modify instance metadata options** → IMDSv2 *Required*.

Then fix **everything else as code**, like a team would:
```bash
terraform apply -var create_instance=true -var secure=true
```
Read the plan first: notice which resources are *modified in place*, *created* (CloudTrail, analyzer, password
policy) and *destroyed* (orphan volume, idle EIP).

## Step 7: verify (5 min)
**Run scan** again → **Strategy**: "Fixed since last scan" lists resolved findings, the attack paths are gone, the
score jumped, the trend chart on Overview shows the improvement. That's the evidence an auditor wants.
Some findings remain on purpose (account-wide things the lab doesn't touch, e.g. GuardDuty in other regions,
Security Hub). Decide: fix, or **suppress with a reason and expiry** (accepted risk) from the finding drawer.

## Step 8: prevent recurrence (10 min)
Strategy → **Guardrails**. Pick "Require IMDSv2 on every new instance". If you use AWS Organizations, create the
SCP; otherwise add the Checkov check to CI and see it fail on a Terraform change that sets `http_tokens =
"optional"`. Also enable `.github/workflows/posture-scan.yml` with the scanner role (OIDC) to scan nightly.

## Step 9: clean up
```bash
terraform destroy -var create_instance=true -var secure=true
```
Dashboard → Accounts → **Remove** the account (deletes the stored, encrypted credentials). Optionally delete the
`terraform-admin` access key. The KMS key goes to "pending deletion" (7 days, no charge).

## Optional: Azure
`infra/terraform/lab-azure/README.md`. `az login`, apply, connect the **service principal**
(tenant/client/secret/subscription), scan, see `AZ-NSG-001`, `AZ-STOR-001/003/005`, `AZ-KV-*`, then
`-var secure=true` and re-scan.

## How to demo this in an interview (5 minutes)
1. *Problem* (20s): misconfigurations cause most cloud breaches; teams drown in findings without priorities.
2. *Live* (3 min): Accounts (read-only role + External ID) → Strategy (attack path with MITRE) → Open in console →
   show the Terraform fix → re-scan → resolved diff and score.
3. *Under the hood* (1 min): rule registry + correlation + deterministic plan, LLM narrates with RAG and redaction;
   MCP for agents.
4. *How it ships* (40s): signed image, Helm + Argo CD, Terraform EKS, CI security gates, Grafana.
