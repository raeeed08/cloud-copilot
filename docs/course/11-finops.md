# 11: FinOps

## What it is
FinOps = engineering, finance and business sharing responsibility for cloud spend. Lifecycle:
**Inform** (visibility, allocation, showback) → **Optimize** (usage + rate) → **Operate** (budgets, governance,
anomaly detection, continuous improvement).

## Where cost data comes from
- AWS **Cost Explorer** API (`ce:GetCostAndUsage`, `GetCostForecast`): `providers/aws/cost.py`. For raw detail:
  **CUR 2.0 / Data Exports** to S3 + Athena.
- Azure **Cost Management** Query API: `providers/azure/cost.py`. Exports to storage for detail.
- Tags (`owner`, `cost-center`, `environment`) must be activated as **cost allocation tags** to group spend.

## Usage optimisation (rules in the project)
| Waste | Rule | Fix |
|---|---|---|
| Unattached volume / managed disk | COST-001, AZ-COST-002 | snapshot then delete |
| gp2 volume | COST-002 | `modify-volume --volume-type gp3` (~20% cheaper, online) |
| Idle public IPv4 | COST-003, AZ-COST-001 | release (AWS bills every public IPv4 since Feb 2024) |
| Old snapshots | COST-004 | lifecycle policies (DLM / AWS Backup) |
| Previous-gen instances | COST-005 | right-size; Graviton |
| Logs that never expire | LOGS-001 | retention |
| No S3 lifecycle | S3-008 | Intelligent-Tiering, expire non-current versions |
| Unused secrets | SM-002 | delete |
Savings estimates use list prices (us-east-1): be honest in interviews that they're **estimates**.

## Rate optimisation
- **Savings Plans** (compute/EC2) and **Reserved Instances**: 1/3-year commitment, up to ~70% off. Cover the steady
  baseline, not peaks. Azure: **Reservations**, **Savings Plan for compute**, **Hybrid Benefit**.
- **Spot / Spot VMs**: up to ~90% off, can be interrupted → stateless, fault-tolerant work (CI, batch, Karpenter).
- **Graviton (ARM)**: better price/performance; we build multi-arch images and run EKS nodes on `m7g`.

## Governance
Budgets with alerts (80/100/120%), Cost Anomaly Detection, mandatory tags enforced by SCP/Azure Policy, schedules
to stop non-prod at night (~65% saving on those resources), Infracost on Terraform PRs, unit economics (cost per
customer/scan).

## Why security and cost in one tool?
The same inventory answers both questions, and many fixes overlap (delete an orphaned public snapshot = less risk
**and** less cost). Owners differ, which is why the strategy puts cost in a parallel "Save money" phase.

## Interview questions
1. **How would you reduce a cloud bill by 30%?** Visibility first (tags, top services), quick usage wins (idle,
   orphaned, oversized, gp3, retention), then commitments for the baseline, Spot for flexible work, architecture
   (serverless, caching, data transfer), governance to keep it.
2. **Savings Plans vs RIs vs Spot?** Flexible commitment vs specific commitment vs interruptible spare capacity.
3. **What is unit economics?** Cost per business unit (per tenant, per transaction): shows efficiency, not just totals.
4. **What hidden costs surprise teams?** NAT gateway data processing, cross-AZ/region transfer, CloudWatch
   ingestion, idle IPv4, snapshots, KMS requests, extended-support Kubernetes versions.

## Exercises
1. In the demo, sort the Cost page by savings and explain the top 3 to a "finance manager" in plain words.
2. Add a rule "NAT gateway in a VPC with no private subnets in use" (design the scanner data first).
