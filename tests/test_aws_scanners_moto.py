"""AWS scanners against moto's in-memory AWS. Proves the boto3 calls and normalisation are right."""

from __future__ import annotations

import json
from collections.abc import Iterator

import boto3
import pytest
from moto import mock_aws

from cloud_copilot.core.registry import RULES, load_all
from cloud_copilot.providers.aws.context import AwsContext
from cloud_copilot.providers.aws.scanners.ec2 import scan_ec2
from cloud_copilot.providers.aws.scanners.iam import scan_iam
from cloud_copilot.providers.aws.scanners.s3 import scan_s3
from cloud_copilot.providers.aws.scanners.services import scan_cloudtrail, scan_dynamodb, scan_kms, scan_rds

load_all()
REGION = "us-east-1"


@pytest.fixture
def ctx() -> Iterator[AwsContext]:
    with mock_aws():
        yield AwsContext(session=boto3.session.Session(region_name=REGION), regions=[REGION], home_region=REGION)


def fired(rule_id: str, data: dict) -> list:
    return list(RULES[rule_id].fn(data))


def test_s3_scanner(ctx: AwsContext) -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_policy(
        Bucket="open-bucket",
        Policy=json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::open-bucket/*",
                    }
                ]
            }
        ),
    )
    s3.create_bucket(Bucket="good-bucket")
    s3.put_public_access_block(
        Bucket="good-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket="good-bucket", VersioningConfiguration={"Status": "Enabled"})

    data = scan_s3(ctx)
    by_name = {b["name"]: b for b in data["buckets"]}
    assert by_name["open-bucket"]["policy"]["public"] is True
    assert by_name["good-bucket"]["versioning"] is True
    assert [h.resource_name for h in fired("S3-002", data)] == ["open-bucket"]
    assert {h.resource_name for h in fired("S3-005", data)} == {"open-bucket"}


def test_ec2_scanner(ctx: AwsContext) -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh-world", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50, VolumeType="gp2")
    ec2.allocate_address(Domain="vpc")

    data = scan_ec2(ctx)
    assert any(s["name"] == "ssh-world" for s in data["security_groups"])
    assert [h.resource_name for h in fired("EC2-001", data)] == ["ssh-world"]
    assert fired("COST-001", data) and fired("COST-002", data) and fired("COST-003", data)
    assert REGION in data["ebs_default_encryption"]
    assert fired("VPC-001", data)  # default VPC has no flow logs


def test_iam_scanner(ctx: AwsContext) -> None:
    iam = boto3.client("iam")
    iam.create_user(UserName="dev")
    iam.create_login_profile(UserName="dev", Password="S3cure-Passw0rd!")
    iam.attach_user_policy(UserName="dev", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="dev")
    pol = iam.create_policy(
        PolicyName="star",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    iam.attach_user_policy(UserName="dev", PolicyArn=pol["Policy"]["Arn"])

    data = scan_iam(ctx)
    (user,) = data["users"]
    assert user["console_access"] and not user["mfa_enabled"] and len(user["access_keys"]) == 1
    assert {p["name"] for p in data["admin_policies"]} == {"star"}
    assert fired("IAM-004", data) and fired("IAM-009", data) and fired("IAM-003", data)


def test_rds_kms_cloudtrail_dynamodb(ctx: AwsContext) -> None:
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="pub-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
        PubliclyAccessible=True,
        StorageEncrypted=False,
        BackupRetentionPeriod=1,
    )
    boto3.client("kms", region_name=REGION).create_key()
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName="t",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    rds_data = scan_rds(ctx)
    assert fired("RDS-001", rds_data) and fired("RDS-002", rds_data) and fired("RDS-004", rds_data)
    assert fired("KMS-001", scan_kms(ctx))
    assert fired("CT-001", scan_cloudtrail(ctx))  # no trail at all
    assert fired("DDB-001", scan_dynamodb(ctx))


def test_region_errors_become_warnings() -> None:
    ctx = AwsContext(session=boto3.session.Session(region_name=REGION), regions=[REGION])

    def boom(region: str) -> list:
        from botocore.exceptions import ClientError

        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Describe")

    assert ctx.for_each_region(boom, "test") == []
    assert ctx.warnings == ["test@us-east-1: AccessDenied"]
