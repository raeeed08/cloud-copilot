# Rule catalogue

_Generated from the rule registry: **103 rules** across **27 services**. Regenerate with `make docs`._

Severity weights for the posture score: CRITICAL 10 · HIGH 6 · MEDIUM 3 · LOW 1 (cost & INFO rules are not scored). Compliance mappings are indicative.

## AWS

### accessanalyzer

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `IAM-011` | LOW | security | IAM Access Analyzer disabled | 1.20 | AC-3, CA-7 |

### acm

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `ACM-001` | HIGH | reliability | Certificate expiring soon |  | SC-17 |

### cloudtrail

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `CT-001` | CRITICAL | security | No multi-region CloudTrail | 3.1 | AU-2, AU-12 |
| `CT-002` | MEDIUM | security | CloudTrail log file validation disabled | 3.2 | AU-9 |
| `CT-003` | HIGH | security | CloudTrail is not logging |  | AU-2, AU-5 |
| `CT-004` | LOW | security | CloudTrail logs not encrypted with KMS | 3.5 | AU-9, SC-28 |
| `CT-005` | LOW | security | CloudTrail not integrated with CloudWatch Logs |  | SI-4, AU-6 |

### detective

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `CFG-001` | MEDIUM | security | AWS Config not recording | 3.3 | CM-8, CM-3 |
| `GD-001` | HIGH | security | GuardDuty disabled |  | SI-4, RA-5 |
| `SH-001` | LOW | security | Security Hub disabled |  | CA-7, SI-4 |

### dynamodb

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `DDB-001` | MEDIUM | reliability | DynamoDB point-in-time recovery disabled |  | CP-9 |
| `DDB-002` | LOW | reliability | DynamoDB deletion protection disabled |  | CP-9 |

### ec2

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `COST-001` | LOW | cost | Unattached EBS volume |  |  |
| `COST-002` | INFO | cost | gp2 volume can move to gp3 |  |  |
| `COST-003` | LOW | cost | Idle Elastic IP |  |  |
| `COST-004` | INFO | cost | Old EBS snapshot (180+ days) |  |  |
| `COST-005` | INFO | cost | Previous-generation instance type |  |  |
| `EBS-001` | MEDIUM | security | EBS encryption by default disabled | 2.2.1 | SC-28 |
| `EBS-002` | MEDIUM | security | EBS volume not encrypted |  | SC-28 |
| `EBS-003` | CRITICAL | security | EBS snapshot is public |  | AC-3, AC-21 |
| `EC2-001` | CRITICAL | security | Admin ports open to the internet | 5.2, 5.3 | SC-7, AC-17 |
| `EC2-002` | CRITICAL | security | Database/cluster ports open to the internet |  | SC-7, AC-3 |
| `EC2-003` | HIGH | security | Security group allows all traffic from the internet |  | SC-7 |
| `EC2-004` | LOW | security | Default security group has rules | 5.4 | SC-7, CM-7 |
| `EC2-005` | MEDIUM | security | IMDSv2 not enforced | 5.6 | SC-7, AC-3 |
| `VPC-001` | MEDIUM | security | VPC flow logs disabled | 3.7 | AU-12, SI-4 |

### ecr

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `ECR-001` | MEDIUM | security | ECR scan on push disabled |  | RA-5 |
| `ECR-002` | LOW | security | ECR tags are mutable |  | CM-14, SI-7 |
| `ECR-003` | HIGH | security | ECR repository is public |  | AC-3 |

### eks

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `EKS-001` | HIGH | security | EKS API endpoint open to the internet |  | SC-7, AC-17 |
| `EKS-002` | MEDIUM | security | EKS control plane logging incomplete |  | AU-2, AU-12 |
| `EKS-003` | MEDIUM | security | EKS secrets not envelope-encrypted |  | SC-28 |

### elb

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `ELB-001` | MEDIUM | security | Load balancer serves plain HTTP |  | SC-8 |
| `ELB-002` | MEDIUM | security | Load balancer allows outdated TLS |  | SC-8, SC-13 |
| `ELB-003` | LOW | security | Load balancer access logs disabled |  | AU-2, AU-12 |
| `ELB-004` | LOW | security | ALB does not drop invalid headers |  | SI-10 |

### iam

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `IAM-001` | CRITICAL | security | Root account has no MFA | 1.5 | IA-2(1) |
| `IAM-002` | CRITICAL | security | Root account has access keys | 1.4 | AC-6(2), IA-4 |
| `IAM-003` | MEDIUM | security | Weak or missing password policy | 1.8, 1.9 | IA-5(1) |
| `IAM-004` | HIGH | security | Console user without MFA | 1.10 | IA-2(1) |
| `IAM-005` | MEDIUM | security | Access key not rotated in 90 days | 1.14 | IA-5(1), AC-2(3) |
| `IAM-006` | MEDIUM | security | Unused credentials (45+ days) | 1.12 | AC-2(3) |
| `IAM-007` | LOW | security | User has more than one active access key | 1.13 | IA-5 |
| `IAM-008` | LOW | security | Policies attached directly to users | 1.15 | AC-2, AC-6 |
| `IAM-009` | HIGH | security | Full administrator privileges granted | 1.16 | AC-6 |
| `IAM-010` | LOW | security | No AWS Support role | 1.17 | IR-7 |

### kms

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `KMS-001` | MEDIUM | security | KMS key rotation disabled | 3.6 | SC-12 |

### lambda

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `LAMBDA-001` | MEDIUM | security | Lambda uses a deprecated runtime |  | SI-2 |
| `LAMBDA-002` | HIGH | security | Lambda is publicly invocable |  | AC-3, SC-7 |
| `LAMBDA-003` | MEDIUM | security | Possible secret in Lambda environment |  | IA-5(7), SC-28 |

### logs

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `LOGS-001` | LOW | cost | Log group without retention |  | AU-11 |

### messaging

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `MSG-001` | LOW | security | Queue or topic not encrypted |  | SC-28 |
| `MSG-002` | HIGH | security | Queue or topic policy is public |  | AC-3 |

### rds

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `RDS-001` | CRITICAL | security | RDS instance publicly accessible | 2.3.3 | SC-7, AC-3 |
| `RDS-002` | HIGH | security | RDS storage not encrypted | 2.3.1 | SC-28 |
| `RDS-003` | CRITICAL | security | RDS snapshot shared publicly |  | AC-3, AC-21 |
| `RDS-004` | MEDIUM | reliability | RDS backups retained less than 7 days |  | CP-9 |
| `RDS-005` | LOW | reliability | RDS deletion protection disabled |  | CP-9, SI-7 |
| `RDS-006` | LOW | security | RDS auto minor version upgrade disabled | 2.3.2 | SI-2 |
| `RDS-007` | LOW | reliability | RDS instance not Multi-AZ |  | CP-7 |

### s3

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `S3-001` | HIGH | security | Account-level S3 Block Public Access disabled | 2.1.4 | AC-3, AC-21 |
| `S3-002` | CRITICAL | security | S3 bucket is publicly accessible | 2.1.4 | AC-3, AC-21, SC-7 |
| `S3-003` | MEDIUM | security | S3 bucket Block Public Access not enabled | 2.1.4 | AC-3 |
| `S3-004` | MEDIUM | security | S3 bucket allows plain HTTP | 2.1.1 | SC-8 |
| `S3-005` | LOW | reliability | S3 bucket versioning disabled |  | CP-9, SI-12 |
| `S3-006` | LOW | security | S3 server access logging disabled |  | AU-2, AU-12 |
| `S3-007` | INFO | security | S3 bucket not encrypted with KMS |  | SC-28, SC-12 |
| `S3-008` | LOW | cost | S3 bucket without lifecycle policy |  |  |

### secretsmanager

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `SM-001` | MEDIUM | security | Secret rotation disabled |  | IA-5(1) |
| `SM-002` | LOW | cost | Unused secret (90+ days) |  | CM-7 |

## Azure

### acr

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-ACR-001` | MEDIUM | security | ACR admin user enabled |  | IA-2, AC-6 |
| `AZ-ACR-002` | LOW | security | ACR public network access enabled |  | SC-7 |

### aks

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-AKS-001` | HIGH | security | AKS API server publicly reachable |  | SC-7, AC-17 |
| `AZ-AKS-002` | MEDIUM | security | AKS local accounts enabled |  | IA-2, AC-2 |
| `AZ-AKS-003` | MEDIUM | security | AKS without network policy |  | SC-7, AC-4 |

### appservice

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-APP-001` | MEDIUM | security | App Service allows HTTP | 9.2 | SC-8 |
| `AZ-APP-002` | MEDIUM | security | App Service allows TLS < 1.2 | 9.3 | SC-8 |
| `AZ-APP-003` | MEDIUM | security | App Service allows plain FTP | 9.10 | SC-8 |
| `AZ-APP-004` | HIGH | security | App Service remote debugging enabled |  | CM-7 |

### compute

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-COST-002` | LOW | cost | Unattached managed disk |  |  |
| `AZ-DISK-001` | MEDIUM | security | Managed disk exportable from any network |  | AC-3, SC-7 |
| `AZ-VM-001` | MEDIUM | security | Linux VM allows password authentication |  | IA-5 |
| `AZ-VM-002` | LOW | security | VM encryption at host disabled |  | SC-28 |

### defender

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-DEF-001` | MEDIUM | security | Defender for Cloud plan on Free tier | 2.1.1 | SI-4, RA-5 |

### keyvault

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-KV-001` | MEDIUM | security | Key Vault purge protection disabled | 8.5 | CP-9, SC-12 |
| `AZ-KV-002` | LOW | security | Key Vault uses access policies instead of RBAC | 8.6 | AC-2, AC-6 |
| `AZ-KV-003` | MEDIUM | security | Key Vault reachable from all networks | 8.7 | SC-7 |

### monitor

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-MON-001` | HIGH | security | No subscription diagnostic setting | 5.1.1 | AU-2, AU-11 |
| `AZ-MON-002` | MEDIUM | security | Missing activity log alerts for critical operations | 5.2.1, 5.2.3, 5.2.4 | SI-4, AU-6 |

### network

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-COST-001` | LOW | cost | Unassociated public IP |  |  |
| `AZ-NSG-001` | CRITICAL | security | Admin ports open to the internet | 6.1, 6.2 | SC-7, AC-17 |
| `AZ-NSG-002` | CRITICAL | security | Database/cluster ports open to the internet |  | SC-7 |
| `AZ-NSG-003` | HIGH | security | NSG allows any port from the internet |  | SC-7 |

### sql

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-SQL-001` | CRITICAL | security | SQL server firewall allows all IPs | 4.1.2 | SC-7 |
| `AZ-SQL-002` | MEDIUM | security | SQL server allows all Azure services |  | SC-7 |
| `AZ-SQL-003` | MEDIUM | security | SQL server auditing disabled | 4.1.1 | AU-2, AU-12 |
| `AZ-SQL-004` | LOW | security | SQL server without Entra ID admin | 4.1.4 | IA-2 |
| `AZ-SQL-005` | MEDIUM | security | SQL server accepts TLS < 1.2 |  | SC-8 |

### storage

| ID | Severity | Category | Title | CIS | NIST 800-53 |
|---|---|---|---|---|---|
| `AZ-STOR-001` | HIGH | security | Storage account allows public blob access | 3.7 | AC-3, AC-21 |
| `AZ-STOR-002` | MEDIUM | security | Storage account accepts HTTP | 3.1 | SC-8 |
| `AZ-STOR-003` | MEDIUM | security | Storage account allows TLS < 1.2 | 3.15 | SC-8, SC-13 |
| `AZ-STOR-004` | LOW | security | Storage account shared key access enabled |  | IA-2, AC-6 |
| `AZ-STOR-005` | MEDIUM | security | Storage account open to all networks | 3.8 | SC-7 |
