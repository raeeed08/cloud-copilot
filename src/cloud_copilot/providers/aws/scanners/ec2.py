"""EC2 & VPC: security groups, instances, EBS volumes/snapshots, Elastic IPs, VPC flow logs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cloud_copilot.core.registry import scanner
from cloud_copilot.models import Provider
from cloud_copilot.providers.aws.context import AwsContext, paginate

WORLD = {"0.0.0.0/0", "::/0"}


def normalise_permissions(perms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten IpPermissions into rules with explicit port ranges and world exposure, per permission."""
    out = []
    for p in perms:
        proto = str(p.get("IpProtocol", "-1"))
        all_ports = proto == "-1" or ("FromPort" not in p and proto in ("tcp", "udp"))
        from_port = 0 if all_ports else int(p.get("FromPort", 0))
        to_port = 65535 if all_ports else int(p.get("ToPort", from_port))
        if proto == "icmp" or proto == "1":
            from_port, to_port = -1, -1
        cidrs = [r.get("CidrIp") for r in p.get("IpRanges", [])] + [r.get("CidrIpv6") for r in p.get("Ipv6Ranges", [])]
        out.append(
            {
                "protocol": proto,
                "from_port": from_port,
                "to_port": to_port,
                "cidrs": [c for c in cidrs if c],
                "open_to_world": any(c in WORLD for c in cidrs),
                "source_groups": [g.get("GroupId") for g in p.get("UserIdGroupPairs", [])],
            }
        )
    return out


def _tag(tags: list[dict[str, str]] | None, key: str = "Name") -> str | None:
    for t in tags or []:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def _scan_region(ctx: AwsContext, region: str) -> list[dict[str, Any]]:
    ec2 = ctx.client("ec2", region)
    sgs = paginate(ec2, "describe_security_groups", "SecurityGroups")
    enis = paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
    used_sgs = {g["GroupId"] for eni in enis for g in eni.get("Groups", [])}

    instances = []
    for res in paginate(ec2, "describe_instances", "Reservations"):
        for i in res["Instances"]:
            instances.append(
                {
                    "id": i["InstanceId"],
                    "name": _tag(i.get("Tags")),
                    "region": region,
                    "state": i["State"]["Name"],
                    "type": i.get("InstanceType"),
                    "public_ip": i.get("PublicIpAddress"),
                    "imdsv2_required": i.get("MetadataOptions", {}).get("HttpTokens") == "required",
                    "instance_profile": bool(i.get("IamInstanceProfile")),
                    "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                    "launch_days": (datetime.now(UTC) - i["LaunchTime"]).days if i.get("LaunchTime") else None,
                }
            )

    volumes = [
        {
            "id": v["VolumeId"],
            "name": _tag(v.get("Tags")),
            "region": region,
            "size_gb": v["Size"],
            "type": v["VolumeType"],
            "encrypted": v.get("Encrypted", False),
            "attached": bool(v.get("Attachments")),
        }
        for v in paginate(ec2, "describe_volumes", "Volumes")
    ]
    snapshots = [
        {
            "id": s["SnapshotId"],
            "region": region,
            "size_gb": s["VolumeSize"],
            "age_days": (datetime.now(UTC) - s["StartTime"]).days,
            "encrypted": s.get("Encrypted", False),
        }
        for s in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
    ]
    public_snapshot_ids = {
        s["SnapshotId"]
        for s in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"], RestorableByUserIds=["all"])
    }
    for s in snapshots:
        s["public"] = s["id"] in public_snapshot_ids

    flow_log_resources = {f["ResourceId"] for f in paginate(ec2, "describe_flow_logs", "FlowLogs")}
    vpcs = [
        {
            "id": v["VpcId"],
            "region": region,
            "is_default": v.get("IsDefault", False),
            "flow_logs": v["VpcId"] in flow_log_resources,
        }
        for v in paginate(ec2, "describe_vpcs", "Vpcs")
    ]

    return [
        {
            "region": region,
            "ebs_encryption_by_default": ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
            "security_groups": [
                {
                    "id": sg["GroupId"],
                    "name": sg["GroupName"],
                    "vpc_id": sg.get("VpcId"),
                    "region": region,
                    "is_default": sg["GroupName"] == "default",
                    "in_use": sg["GroupId"] in used_sgs,
                    "ingress": normalise_permissions(sg.get("IpPermissions", [])),
                }
                for sg in sgs
            ],
            "instances": instances,
            "volumes": volumes,
            "snapshots": snapshots,
            "addresses": [
                {
                    "ip": a.get("PublicIp"),
                    "allocation_id": a.get("AllocationId", a.get("PublicIp")),
                    "region": region,
                    "associated": bool(a.get("AssociationId")),
                }
                for a in ec2.describe_addresses().get("Addresses", [])
            ],
            "vpcs": vpcs,
        }
    ]


@scanner(Provider.AWS, "ec2", "EC2, EBS, security groups, Elastic IPs, VPC flow logs (all regions)")
def scan_ec2(ctx: AwsContext) -> dict[str, Any]:
    regions = ctx.for_each_region(lambda r: _scan_region(ctx, r), "ec2")
    merged: dict[str, Any] = {"ebs_default_encryption": {r["region"]: r["ebs_encryption_by_default"] for r in regions}}
    for key in ("security_groups", "instances", "volumes", "snapshots", "addresses", "vpcs"):
        merged[key] = [item for r in regions for item in r[key]]
    return merged
