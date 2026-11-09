# FinOps playbook: cloud cost optimisation

## The FinOps loop
**Inform** (visibility, allocation via tags, showback), **Optimize** (rates and usage), **Operate** (budgets,
anomaly detection, governance). Cost findings in Cloud Copilot (category `cost`) feed the Optimize phase with an
estimated monthly saving per resource.

## Quick wins (usage)
- Unattached EBS volumes / Azure managed disks (COST-001, AZ-COST-002): snapshot then delete.
- gp2 → gp3 (COST-002): about 20% cheaper with baseline 3,000 IOPS / 125 MB/s, online migration with
  `aws ec2 modify-volume --volume-type gp3`.
- Idle Elastic IPs / public IPs (COST-003, AZ-COST-001): since Feb 2024 AWS bills every public IPv4 at
  $0.005/hour.
- Old snapshots (COST-004): Data Lifecycle Manager / AWS Backup retention policies.
- Log groups without retention (LOGS-001): CloudWatch ingestion and storage often become a top-5 cost line.
- S3 lifecycle rules and Intelligent-Tiering for data with unknown access patterns (S3-008).
- Previous-generation instances (COST-005): move to current families, Graviton (arm64) for 20–40% better
  price-performance.

## Rate optimisation
- Compute Savings Plans (1 or 3 years) for steady baseline. Cover around 70–80% of the 24/7 floor, never peaks.
- Azure Reservations / Savings Plan for compute; Azure Hybrid Benefit for Windows/SQL licences.
- Spot instances / Spot VMs for stateless, fault-tolerant workloads (CI runners, batch, Karpenter node pools).

## Governance
- Mandatory tags (`owner`, `cost-center`, `environment`) enforced via SCP/Azure Policy, activated as cost
  allocation tags.
- AWS Budgets / Azure Budgets with alerts at 80/100/120% and Cost Anomaly Detection.
- Schedule non-production environments off at night and weekends (Instance Scheduler, AKS stop/start). That alone
  saves ~65% of their compute cost.
