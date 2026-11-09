# Network exposure: security groups, NSGs and admin access

## Why 0.0.0.0/0 on admin ports is critical
Internet-wide scanners (Shodan, masscan botnets) find a new open SSH/RDP port within minutes. Brute force,
credential stuffing and pre-auth exploits (e.g. BlueKeep for RDP, regreSSHion CVE-2024-6387 for OpenSSH) follow.
Rules EC2-001 and AZ-NSG-001 flag these. Databases and control planes (5432, 3306, 6379, 9200, 27017, 6443,
2375) are flagged by EC2-002 and AZ-NSG-002: ransomware gangs routinely wipe exposed MongoDB/Elasticsearch.

## Replace bastions with identity-aware access
- **AWS Systems Manager Session Manager**: no inbound ports, IAM-authorised, sessions logged to S3/CloudWatch.
  `aws ssm start-session --target i-0123` and port forwarding for databases
  (`AWS-StartPortForwardingSessionToRemoteHost`).
- **EC2 Instance Connect Endpoint**: SSH to private instances without a public IP.
- **Azure Bastion** or **Just-In-Time VM access** (Defender for Servers) opens 22/3389 for a time-boxed window to
  one source IP after approval.

## Security group hygiene
- Reference security groups instead of CIDRs between tiers (ALB SG → app SG → DB SG).
- Keep the VPC default security group empty (rule EC2-004, CIS 5.4) so forgotten resources are isolated.
- Use AWS Firewall Manager or Azure Policy (`deny` effect) to block world-open admin ports at creation time.
- Enable VPC flow logs (VPC-001) / NSG flow logs → Traffic Analytics to detect scanning and exfiltration.

## Terraform guardrail example (OPA/Conftest)
```rego
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_vpc_security_group_ingress_rule"
  r.change.after.cidr_ipv4 == "0.0.0.0/0"
  r.change.after.from_port <= 22
  r.change.after.to_port >= 22
  msg := sprintf("%s opens SSH to the internet", [r.address])
}
```
