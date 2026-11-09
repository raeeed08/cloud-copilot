"""
Synthetic multi-cloud estate for demos, screenshots and end-to-end tests.

The data has exactly the shape produced by the real scanners, so the *real* rule engine, scoring, LLM and
dashboard run on it unchanged. IDs and names are fictitious ("acme" is a placeholder company).
"""

from __future__ import annotations

import copy
from typing import Any

from cloud_copilot.models import CostSummary, Provider

ACCOUNT = "111122223333"
SUB = "00000000-1111-2222-3333-444444444444"
ACCOUNTS = {Provider.AWS: ACCOUNT, Provider.AZURE: SUB}
EU, US = "eu-west-1", "us-east-1"
FULL_PAB = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def _user(
    name: str,
    *,
    console: bool,
    mfa: bool,
    keys: list[tuple[int, int | None]],
    policies: list[str],
    inline: list[str] | None = None,
    pw_used: int | None = 3,
) -> dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "age_days": 400,
        "console_access": console,
        "password_last_used_days": pw_used if console else None,
        "mfa_enabled": mfa,
        "access_keys": [
            {"id": f"AKIADEMO{name.upper()[:6]}{i:04d}", "status": "Active", "age_days": age, "last_used_days": used}
            for i, (age, used) in enumerate(keys)
        ],
        "attached_policies": policies,
        "inline_policies": inline or [],
        "groups": [],
    }


def _sg(
    id_: str,
    name: str,
    region: str,
    ingress: list[tuple[str, int, int, str]],
    *,
    default: bool = False,
    in_use: bool = True,
) -> dict[str, Any]:
    return {
        "id": id_,
        "name": name,
        "vpc_id": "vpc-0a1b2c3d",
        "region": region,
        "is_default": default,
        "in_use": in_use,
        "ingress": [
            {
                "protocol": p,
                "from_port": f,
                "to_port": t,
                "cidrs": [c],
                "open_to_world": c in ("0.0.0.0/0", "::/0"),
                "source_groups": [],
            }
            for p, f, t, c in ingress
        ],
    }


AWS_DATA: dict[str, dict[str, Any]] = {
    "iam": {
        "root": {"mfa_enabled": True, "access_keys_present": False},
        "password_policy": {"MinimumPasswordLength": 8, "PasswordReusePrevention": 0},
        "users": [
            _user("alice.admin", console=True, mfa=True, keys=[], policies=[], pw_used=1),
            _user("bob.dev", console=True, mfa=False, keys=[(212, 2)], policies=["AdministratorAccess"]),
            _user(
                "ci-deployer",
                console=False,
                mfa=False,
                keys=[(510, 1)],
                policies=["AmazonS3FullAccess", "AmazonECS_FullAccess"],
            ),
            _user("legacy-backup", console=False, mfa=False, keys=[(900, 300)], policies=[], inline=["backup-inline"]),
            _user("carol.analyst", console=True, mfa=True, keys=[], policies=[], pw_used=120),
        ],
        "admin_policies": [{"name": "PowerUsersStar", "arn": f"arn:aws:iam::{ACCOUNT}:policy/PowerUsersStar"}],
        "support_role_exists": True,
    },
    "accessanalyzer": {"regions": [{"region": EU, "enabled": True}, {"region": US, "enabled": True}]},
    "s3": {
        "account_public_access_block": None,
        "buckets": [
            {
                "name": "acme-public-assets",
                "region": EU,
                "public_access_block": None,
                "policy": {"public": True, "enforces_tls": False},
                "acl_public": False,
                "encryption": "AES256",
                "versioning": False,
                "mfa_delete": False,
                "logging": False,
                "lifecycle_rules": 0,
            },
            {
                "name": "acme-customer-exports",
                "region": EU,
                "public_access_block": None,
                "policy": {"public": False, "enforces_tls": False},
                "acl_public": True,
                "encryption": "AES256",
                "versioning": False,
                "mfa_delete": False,
                "logging": False,
                "lifecycle_rules": 0,
            },
            {
                "name": "acme-datalake-raw",
                "region": EU,
                "public_access_block": FULL_PAB,
                "policy": {"public": False, "enforces_tls": True},
                "acl_public": False,
                "encryption": "aws:kms",
                "versioning": True,
                "mfa_delete": False,
                "logging": True,
                "lifecycle_rules": 2,
            },
            {
                "name": "acme-terraform-state",
                "region": US,
                "public_access_block": FULL_PAB,
                "policy": {"public": False, "enforces_tls": True},
                "acl_public": False,
                "encryption": "aws:kms",
                "versioning": True,
                "mfa_delete": False,
                "logging": False,
                "lifecycle_rules": 1,
            },
        ],
    },
    "ec2": {
        "ebs_default_encryption": {EU: True, US: True},
        "security_groups": [
            _sg("sg-0a11bastion", "bastion-ssh", EU, [("tcp", 22, 22, "0.0.0.0/0")]),
            _sg("sg-0b22legacy", "legacy-windows", US, [("tcp", 3389, 3389, "0.0.0.0/0")], in_use=False),
            _sg("sg-0c33db", "reporting-db", EU, [("tcp", 5432, 5432, "0.0.0.0/0")]),
            _sg("sg-0d44debug", "debug-all-open", US, [("-1", 0, 65535, "0.0.0.0/0")]),
            _sg("sg-0e55web", "web-alb", EU, [("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 80, 80, "0.0.0.0/0")]),
            _sg("sg-0f66def", "default", EU, [], default=True),
        ],
        "instances": [
            {
                "id": "i-0aa1",
                "name": "bastion",
                "region": EU,
                "state": "running",
                "type": "t3.micro",
                "public_ip": "198.51.100.10",
                "imdsv2_required": False,
                "instance_profile": True,
                "security_groups": ["sg-0a11bastion"],
                "launch_days": 300,
            },
            {
                "id": "i-0bb2",
                "name": "api-1",
                "region": EU,
                "state": "running",
                "type": "m7g.large",
                "public_ip": None,
                "imdsv2_required": True,
                "instance_profile": True,
                "security_groups": ["sg-0e55web"],
                "launch_days": 20,
            },
            {
                "id": "i-0cc3",
                "name": "legacy-reporting",
                "region": US,
                "state": "running",
                "type": "m4.xlarge",
                "public_ip": "198.51.100.22",
                "imdsv2_required": False,
                "instance_profile": False,
                "security_groups": ["sg-0d44debug"],
                "launch_days": 1400,
            },
        ],
        "volumes": [
            {
                "id": "vol-0a1",
                "name": "bastion-root",
                "region": EU,
                "size_gb": 20,
                "type": "gp3",
                "encrypted": True,
                "attached": True,
            },
            {
                "id": "vol-0b2",
                "name": "legacy-data",
                "region": US,
                "size_gb": 500,
                "type": "gp2",
                "encrypted": False,
                "attached": True,
            },
            {
                "id": "vol-0c3",
                "name": "old-migration",
                "region": US,
                "size_gb": 1000,
                "type": "gp2",
                "encrypted": False,
                "attached": False,
            },
            {
                "id": "vol-0d4",
                "name": None,
                "region": EU,
                "size_gb": 200,
                "type": "io1",
                "encrypted": True,
                "attached": False,
            },
        ],
        "snapshots": [
            {"id": "snap-0a1", "region": US, "size_gb": 500, "age_days": 700, "encrypted": False, "public": False},
            {"id": "snap-0b2", "region": EU, "size_gb": 100, "age_days": 30, "encrypted": True, "public": False},
            {"id": "snap-0c3", "region": EU, "size_gb": 250, "age_days": 400, "encrypted": True, "public": False},
        ],
        "addresses": [
            {"ip": "203.0.113.50", "allocation_id": "eipalloc-0a1", "region": EU, "associated": True},
            {"ip": "203.0.113.51", "allocation_id": "eipalloc-0b2", "region": US, "associated": False},
            {"ip": "203.0.113.52", "allocation_id": "eipalloc-0c3", "region": US, "associated": False},
        ],
        "vpcs": [
            {"id": "vpc-0a1b2c3d", "region": EU, "is_default": False, "flow_logs": True},
            {"id": "vpc-0default", "region": US, "is_default": True, "flow_logs": False},
        ],
    },
    "cloudtrail": {
        "trails": [
            {
                "name": "eu-only-trail",
                "arn": f"arn:aws:cloudtrail:{EU}:{ACCOUNT}:trail/eu-only-trail",
                "region": EU,
                "multi_region": False,
                "log_validation": False,
                "is_logging": True,
                "kms_key": None,
                "cloudwatch_logs": False,
                "management_events": True,
                "s3_bucket": "acme-trail-logs",
            },
        ]
    },
    "rds": {
        "instances": [
            {
                "id": "reporting-pg",
                "region": EU,
                "engine": "postgres",
                "engine_version": "13.7",
                "public": True,
                "encrypted": False,
                "backup_retention_days": 1,
                "multi_az": False,
                "deletion_protection": False,
                "auto_minor_upgrade": False,
                "iam_auth": False,
                "security_groups": ["sg-0c33db"],
            },
            {
                "id": "orders-aurora",
                "region": EU,
                "engine": "aurora-postgresql",
                "engine_version": "16.4",
                "public": False,
                "encrypted": True,
                "backup_retention_days": 14,
                "multi_az": True,
                "deletion_protection": True,
                "auto_minor_upgrade": True,
                "iam_auth": True,
                "security_groups": ["sg-0e55web"],
            },
        ],
        "snapshots": [{"id": "reporting-pg-manual-2023", "region": EU, "public": False, "encrypted": False}],
    },
    "kms": {
        "keys": [
            {
                "id": "1234abcd-demo",
                "arn": f"arn:aws:kms:{EU}:{ACCOUNT}:key/1234abcd-demo",
                "region": EU,
                "symmetric": True,
                "rotation_enabled": True,
            },
            {
                "id": "5678efgh-demo",
                "arn": f"arn:aws:kms:{EU}:{ACCOUNT}:key/5678efgh-demo",
                "region": EU,
                "symmetric": True,
                "rotation_enabled": True,
            },
        ]
    },
    "lambda": {
        "functions": [
            {
                "name": "thumbnailer",
                "arn": f"arn:aws:lambda:{EU}:{ACCOUNT}:function:thumbnailer",
                "region": EU,
                "runtime": "python3.8",
                "url_auth_none": True,
                "public_policy": False,
                "env_var_names": ["BUCKET", "STRIPE_API_KEY"],
            },
            {
                "name": "orders-api",
                "arn": f"arn:aws:lambda:{EU}:{ACCOUNT}:function:orders-api",
                "region": EU,
                "runtime": "python3.12",
                "url_auth_none": False,
                "public_policy": False,
                "env_var_names": ["TABLE"],
            },
        ]
    },
    "detective": {
        "regions": [
            {"region": EU, "guardduty": True, "config_recording": True, "securityhub": True},
            {"region": US, "guardduty": False, "config_recording": True, "securityhub": True},
        ]
    },
    "elb": {
        "load_balancers": [
            {
                "name": "web-alb",
                "arn": f"arn:aws:elasticloadbalancing:{EU}:{ACCOUNT}:loadbalancer/app/web-alb/1",
                "region": EU,
                "type": "application",
                "internet_facing": True,
                "http_without_redirect": 1,
                "ssl_policies": ["ELBSecurityPolicy-2016-08"],
                "access_logs": True,
                "deletion_protection": True,
                "drop_invalid_headers": True,
            },
        ]
    },
    "eks": {
        "clusters": [
            {
                "name": "platform-prod",
                "arn": f"arn:aws:eks:{EU}:{ACCOUNT}:cluster/platform-prod",
                "region": EU,
                "version": "1.29",
                "public_endpoint": True,
                "public_cidrs": ["198.51.100.0/24"],
                "log_types": ["api", "audit", "authenticator"],
                "secrets_encryption": True,
            },
        ]
    },
    "ecr": {
        "repositories": [
            {
                "name": "cloud-copilot",
                "arn": f"arn:aws:ecr:{EU}:{ACCOUNT}:repository/cloud-copilot",
                "region": EU,
                "scan_on_push": True,
                "immutable_tags": True,
                "public_policy": False,
            },
            {
                "name": "legacy-worker",
                "arn": f"arn:aws:ecr:{EU}:{ACCOUNT}:repository/legacy-worker",
                "region": EU,
                "scan_on_push": True,
                "immutable_tags": True,
                "public_policy": False,
            },
        ]
    },
    "dynamodb": {
        "tables": [
            {
                "name": "sessions",
                "arn": f"arn:aws:dynamodb:{EU}:{ACCOUNT}:table/sessions",
                "region": EU,
                "pitr": False,
                "deletion_protection": True,
                "kms": False,
            },
        ]
    },
    "secretsmanager": {
        "secrets": [
            {
                "name": "prod/db/reporting",
                "arn": f"arn:aws:secretsmanager:{EU}:{ACCOUNT}:secret:prod/db/reporting",
                "region": EU,
                "rotation_enabled": False,
                "last_accessed_days": 1,
            },
            {
                "name": "old/partner-api",
                "arn": f"arn:aws:secretsmanager:{EU}:{ACCOUNT}:secret:old/partner-api",
                "region": EU,
                "rotation_enabled": False,
                "last_accessed_days": 240,
            },
        ]
    },
    "messaging": {
        "resources": [
            {
                "kind": "sqs",
                "name": "orders-queue",
                "arn": f"arn:aws:sqs:{EU}:{ACCOUNT}:orders-queue",
                "region": EU,
                "encrypted": True,
                "public_policy": False,
            },
            {
                "kind": "sns",
                "name": "alerts",
                "arn": f"arn:aws:sns:{EU}:{ACCOUNT}:alerts",
                "region": EU,
                "encrypted": True,
                "public_policy": True,
            },
        ]
    },
    "logs": {
        "log_groups": [
            {
                "name": "/aws/lambda/thumbnailer",
                "arn": "lg-1",
                "region": EU,
                "retention_days": None,
                "stored_gb": 85.0,
                "kms": False,
            },
            {"name": "/ecs/api", "arn": "lg-2", "region": EU, "retention_days": 30, "stored_gb": 4.2, "kms": False},
        ]
    },
    "acm": {
        "certificates": [
            {
                "arn": f"arn:aws:acm:{EU}:{ACCOUNT}:certificate/demo-1",
                "domain": "api.acme.example",
                "region": EU,
                "status": "ISSUED",
                "in_use": True,
                "days_to_expiry": 12,
            },
        ]
    },
}


def _az(kind: str, name: str, rg: str = "rg-prod") -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{kind}/{name}"


AZURE_DATA: dict[str, dict[str, Any]] = {
    "storage": {
        "accounts": [
            {
                "id": _az("Microsoft.Storage/storageAccounts", "acmeprodlogs"),
                "name": "acmeprodlogs",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "allow_blob_public_access": True,
                "https_only": True,
                "min_tls": "TLS1_0",
                "shared_key_access": True,
                "network_default_action": "Allow",
                "public_network_access": "Enabled",
                "infrastructure_encryption": False,
            },
            {
                "id": _az("Microsoft.Storage/storageAccounts", "acmedatalake"),
                "name": "acmedatalake",
                "resource_group": "rg-data",
                "location": "westeurope",
                "allow_blob_public_access": False,
                "https_only": True,
                "min_tls": "TLS1_2",
                "shared_key_access": False,
                "network_default_action": "Deny",
                "public_network_access": "Disabled",
                "infrastructure_encryption": True,
            },
        ]
    },
    "network": {
        "nsgs": [
            {
                "id": _az("Microsoft.Network/networkSecurityGroups", "nsg-jumpbox"),
                "name": "nsg-jumpbox",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "inbound_allow": [
                    {
                        "name": "allow-rdp",
                        "priority": 100,
                        "protocol": "Tcp",
                        "ports": ["3389"],
                        "sources": ["Internet"],
                        "from_internet": True,
                    }
                ],
            },
            {
                "id": _az("Microsoft.Network/networkSecurityGroups", "nsg-app"),
                "name": "nsg-app",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "inbound_allow": [
                    {
                        "name": "allow-https",
                        "priority": 100,
                        "protocol": "Tcp",
                        "ports": ["443"],
                        "sources": ["Internet"],
                        "from_internet": True,
                    },
                    {
                        "name": "allow-mgmt",
                        "priority": 110,
                        "protocol": "*",
                        "ports": ["1-65535"],
                        "sources": ["*"],
                        "from_internet": True,
                    },
                ],
            },
        ],
        "public_ips": [
            {
                "id": _az("Microsoft.Network/publicIPAddresses", "pip-old-lb"),
                "name": "pip-old-lb",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "associated": False,
                "sku": "Standard",
            },
        ],
    },
    "keyvault": {
        "vaults": [
            {
                "id": _az("Microsoft.KeyVault/vaults", "kv-acme-prod"),
                "name": "kv-acme-prod",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "soft_delete": True,
                "purge_protection": False,
                "rbac": True,
                "public_network_access": "Enabled",
                "network_default_action": "Allow",
            },
        ]
    },
    "sql": {
        "servers": [
            {
                "id": _az("Microsoft.Sql/servers", "sql-acme-crm"),
                "name": "sql-acme-crm",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "public_network_access": "Enabled",
                "min_tls": "1.2",
                "allow_all_ips": True,
                "allow_azure_services": True,
                "aad_admin": True,
                "auditing": False,
            },
        ]
    },
    "compute": {
        "vms": [
            {
                "id": _az("Microsoft.Compute/virtualMachines", "vm-jumpbox"),
                "name": "vm-jumpbox",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "encryption_at_host": True,
                "secure_boot": False,
                "password_auth": True,  # nosec B105
                "managed_identity": False,
            },
        ],
        "disks": [
            {
                "id": _az("Microsoft.Compute/disks", "disk-old-sql"),
                "name": "disk-old-sql",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "state": "Unattached",
                "size_gb": 1024,
                "sku": "Premium_LRS",
                "network_access_policy": "DenyAll",
                "encryption": "EncryptionAtRestWithPlatformKey",
            },
        ],
    },
    "appservice": {
        "apps": [
            {
                "id": _az("Microsoft.Web/sites", "acme-portal"),
                "name": "acme-portal",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "kind": "app,linux",
                "https_only": False,
                "min_tls": "1.2",
                "ftps_state": "AllAllowed",
                "remote_debugging": True,
                "managed_identity": True,
            },
        ]
    },
    "monitor": {
        "subscriptions": [
            {
                "id": f"/subscriptions/{SUB}",
                "diagnostic_settings": False,
                "alert_operations": ["microsoft.network/networksecuritygroups/write"],
            },
        ]
    },
    "defender": {
        "subscriptions": [
            {
                "id": f"/subscriptions/{SUB}",
                "plans": {
                    "VirtualMachines": "Standard",
                    "SqlServers": "Free",
                    "AppServices": "Free",
                    "StorageAccounts": "Standard",
                    "KeyVaults": "Free",
                    "Containers": "Free",
                    "Arm": "Free",
                },
            },
        ]
    },
    "aks": {
        "clusters": [
            {
                "id": _az("Microsoft.ContainerService/managedClusters", "aks-prod"),
                "name": "aks-prod",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "rbac": True,
                "local_accounts_disabled": False,
                "private": False,
                "authorized_ranges": [],
                "network_policy": "cilium",
                "version": "1.29.4",
            },
        ]
    },
    "acr": {
        "registries": [
            {
                "id": _az("Microsoft.ContainerRegistry/registries", "acracme"),
                "name": "acracme",
                "resource_group": "rg-prod",
                "location": "westeurope",
                "admin_user": True,
                "public_network_access": "Disabled",
                "sku": "Premium",
            },
        ]
    },
}


def data(provider: Provider, service: str) -> dict[str, Any]:
    source = AWS_DATA if provider is Provider.AWS else AZURE_DATA
    payload = copy.deepcopy(source[service])
    if provider is Provider.AZURE:
        for items in payload.values():
            for item in items if isinstance(items, list) else []:
                item.setdefault("subscription", SUB)
    return payload


def costs(provider: Provider) -> CostSummary:
    if provider is Provider.AWS:
        services = [
            ("Amazon Elastic Compute Cloud - Compute", 1840.22),
            ("Amazon Relational Database Service", 912.4),
            ("Amazon Elastic Kubernetes Service", 438.0),
            ("EC2 - Other", 301.75),
            ("Amazon Simple Storage Service", 214.9),
            ("AmazonCloudWatch", 133.1),
            ("Elastic Load Balancing", 92.3),
            ("AWS Lambda", 18.6),
        ]
        total = round(sum(a for _, a in services), 2)
        return CostSummary(
            provider=provider,
            period_start="2026-10-10",
            period_end="2026-11-09",
            total=total,
            forecast_month_end=round(total * 1.04, 2),
            by_service=[{"service": s, "amount": a} for s, a in services],
        )
    services = [
        ("Virtual Machines", 690.0),
        ("Azure Kubernetes Service", 402.5),
        ("SQL Database", 377.8),
        ("Storage", 141.2),
        ("Azure App Service", 96.0),
        ("Bandwidth", 41.3),
    ]
    return CostSummary(
        provider=provider,
        currency="USD",
        period_start="2026-10-10",
        period_end="2026-11-09",
        total=round(sum(a for _, a in services), 2),
        by_service=[{"service": s, "amount": a} for s, a in services],
    )
