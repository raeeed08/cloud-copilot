"""Behavioural tests for the trickiest AWS rules (the ones v1 got wrong)."""

import json
from typing import Any

from cloud_copilot.core.registry import RULES, load_all
from cloud_copilot.models import Severity
from cloud_copilot.providers.aws.scanners.ec2 import normalise_permissions
from cloud_copilot.providers.aws.scanners.iam import grants_full_admin
from cloud_copilot.providers.aws.scanners.s3 import analyse_policy

load_all()


def run(rule_id: str, data: dict[str, Any]) -> list[Any]:
    return list(RULES[rule_id].fn(data))


def sg(perms: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    base = {
        "id": "sg-1",
        "name": "test",
        "vpc_id": "vpc-1",
        "region": "eu-west-1",
        "is_default": False,
        "in_use": True,
        "ingress": normalise_permissions(perms),
    }
    return base | kw


WORLD = [{"CidrIp": "0.0.0.0/0"}]


class TestSecurityGroups:
    def test_ssh_open_to_private_range_and_https_world_is_not_flagged(self) -> None:
        # v1 bug: any world-open rule + any port-22 rule => false positive
        perms = [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": WORLD},
        ]
        assert run("EC2-001", {"security_groups": [sg(perms)]}) == []

    def test_all_traffic_rule_exposes_admin_ports(self) -> None:
        # v1 bug: protocol -1 has no FromPort and was missed
        hits = run("EC2-001", {"security_groups": [sg([{"IpProtocol": "-1", "IpRanges": WORLD}])]})
        assert hits and "SSH (22)" in hits[0].message and "RDP (3389)" in hits[0].message
        assert run("EC2-003", {"security_groups": [sg([{"IpProtocol": "-1", "IpRanges": WORLD}])]})

    def test_port_range_covering_ssh_is_flagged(self) -> None:
        perms = [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 1024, "IpRanges": WORLD}]
        assert run("EC2-001", {"security_groups": [sg(perms)]})

    def test_ipv6_world(self) -> None:
        perms = [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
        assert run("EC2-001", {"security_groups": [sg(perms)]})

    def test_unused_group_is_downgraded(self) -> None:
        perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": WORLD}]
        (hit,) = run("EC2-001", {"security_groups": [sg(perms, in_use=False)]})
        assert hit.severity is Severity.HIGH

    def test_database_port(self) -> None:
        perms = [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": WORLD}]
        (hit,) = run("EC2-002", {"security_groups": [sg(perms)]})
        assert "PostgreSQL" in hit.message

    def test_icmp_is_ignored(self) -> None:
        perms = [{"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": WORLD}]
        assert run("EC2-001", {"security_groups": [sg(perms)]}) == []


class TestS3:
    def test_policy_analysis(self) -> None:
        public = json.dumps(
            {
                "Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
                ]
            }
        )
        conditioned = json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:*",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
                    }
                ]
            }
        )
        tls = json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            }
        )
        assert analyse_policy(public) == {"public": True, "enforces_tls": False}
        assert analyse_policy(conditioned)["public"] is False
        assert analyse_policy(tls) == {"public": False, "enforces_tls": True}
        assert analyse_policy(None) == {"public": False, "enforces_tls": False}

    def test_account_level_block_overrides_bucket_exposure(self) -> None:
        full = dict.fromkeys(
            ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
        )
        bucket = {
            "name": "b",
            "region": "eu-west-1",
            "public_access_block": None,
            "policy": {"public": True, "enforces_tls": False},
            "acl_public": False,
        }
        assert run("S3-002", {"account_public_access_block": None, "buckets": [bucket]})
        assert run("S3-002", {"account_public_access_block": full, "buckets": [bucket]}) == []


class TestIAM:
    def test_full_admin_detection(self) -> None:
        assert grants_full_admin({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        assert grants_full_admin({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}})
        assert not grants_full_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
        assert not grants_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})

    def test_mfa_only_for_console_users(self) -> None:
        users = [
            {"name": "svc", "arn": "a1", "console_access": False, "mfa_enabled": False, "access_keys": []},
            {"name": "human", "arn": "a2", "console_access": True, "mfa_enabled": False, "access_keys": []},
        ]
        hits = run("IAM-004", {"users": users})
        assert [h.resource_name for h in hits] == ["human"]

    def test_unused_key_never_used(self) -> None:
        user = {
            "name": "u",
            "arn": "a",
            "console_access": False,
            "age_days": 100,
            "access_keys": [{"id": "AKIA1234567890", "status": "Active", "age_days": 60, "last_used_days": None}],
        }
        assert run("IAM-006", {"users": [user]})
        user["access_keys"][0]["age_days"] = 10
        assert run("IAM-006", {"users": [user]}) == []

    def test_password_policy(self) -> None:
        assert run("IAM-003", {"password_policy": None})
        strong = {"MinimumPasswordLength": 16, "PasswordReusePrevention": 24}
        assert run("IAM-003", {"password_policy": strong}) == []


def test_acm_escalates_when_imminent() -> None:
    cert = {"arn": "c", "domain": "x.example", "region": "eu-west-1", "in_use": True, "days_to_expiry": 3}
    (hit,) = run("ACM-001", {"certificates": [cert]})
    assert hit.severity is Severity.CRITICAL


def test_cost_savings_estimates() -> None:
    vols = [
        {"id": "v", "name": None, "region": "r", "size_gb": 100, "type": "gp2", "encrypted": True, "attached": False}
    ]
    (unattached,) = run("COST-001", {"volumes": vols})
    (gp3,) = run("COST-002", {"volumes": vols})
    assert unattached.monthly_savings == 10.0 and gp3.monthly_savings == 2.0
