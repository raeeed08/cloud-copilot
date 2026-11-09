"""AWS compute & network rules (security groups, EC2, EBS, Elastic IPs, Lambda) plus cost-waste checks."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Category, Provider, Severity

AWS = Provider.AWS

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
DATA_PORTS = {
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    2375: "Docker API",
    6443: "Kubernetes API",
}

# Approximate us-east-1 list prices (USD / month) used for savings estimates.
EBS_GB_MONTH = {"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05}
SNAPSHOT_GB_MONTH = 0.05
EIP_IDLE_MONTH = 3.65
PREVIOUS_GEN = ("t1.", "t2.", "m1.", "m2.", "m3.", "m4.", "c1.", "c3.", "c4.", "r3.", "r4.", "i2.")

SG_TF = (
    'resource "aws_vpc_security_group_ingress_rule" "restricted" {\n'
    '  security_group_id = "{resource}"\n  cidr_ipv4         = "203.0.113.0/24" # trusted range only\n'
    '  from_port         = 443\n  to_port           = 443\n  ip_protocol       = "tcp"\n}'
)


def exposed_ports(sg: dict[str, Any], ports: dict[int, str]) -> list[str]:
    """Names of sensitive ports reachable from the world through *the same* ingress permission."""
    hits = set()
    for perm in sg["ingress"]:
        if not perm["open_to_world"] or perm["protocol"] in ("icmp", "1", "58", "icmpv6"):
            continue
        for port, label in ports.items():
            if perm["from_port"] <= port <= perm["to_port"]:
                hits.add(f"{label} ({port})")
    return sorted(hits)


@rule(
    id="EC2-001",
    title="Admin ports open to the internet",
    provider=AWS,
    service="ec2",
    severity=Severity.CRITICAL,
    description="SSH/RDP/WinRM reachable from 0.0.0.0/0 or ::/0 are scanned and brute-forced within minutes.",
    remediation="Remove the world-open rule. Use SSM Session Manager, EC2 Instance Connect Endpoint or a VPN.",
    cis=["5.2", "5.3"],
    nist=["SC-7", "AC-17"],
    terraform=SG_TF,
)
def admin_ports(d: dict[str, Any]) -> Iterator[Hit]:
    for sg in d["security_groups"]:
        ports = exposed_ports(sg, ADMIN_PORTS)
        if ports:
            yield Hit(
                sg["id"],
                f"Security group '{sg['name']}' exposes {', '.join(ports)} to the internet.",
                resource_name=sg["name"],
                region=sg["region"],
                details={"ports": ports, "in_use": sg["in_use"]},
                severity=None if sg["in_use"] else Severity.HIGH,
            )


@rule(
    id="EC2-002",
    title="Database/cluster ports open to the internet",
    provider=AWS,
    service="ec2",
    severity=Severity.CRITICAL,
    description="Data stores and control planes should never be reachable from the internet.",
    remediation="Restrict the ingress source to the application security group.",
    nist=["SC-7", "AC-3"],
    terraform=SG_TF,
)
def data_ports(d: dict[str, Any]) -> Iterator[Hit]:
    for sg in d["security_groups"]:
        ports = exposed_ports(sg, DATA_PORTS)
        if ports:
            yield Hit(
                sg["id"],
                f"Security group '{sg['name']}' exposes {', '.join(ports)} to the internet.",
                resource_name=sg["name"],
                region=sg["region"],
                details={"ports": ports},
            )


@rule(
    id="EC2-003",
    title="Security group allows all traffic from the internet",
    provider=AWS,
    service="ec2",
    severity=Severity.HIGH,
    description="An all-protocol or full port-range rule from 0.0.0.0/0 removes the network boundary.",
    remediation="Replace with explicit ports (usually 80/443 behind a load balancer).",
    nist=["SC-7"],
    terraform=SG_TF,
)
def all_traffic(d: dict[str, Any]) -> Iterator[Hit]:
    for sg in d["security_groups"]:
        if any(p["open_to_world"] and p["from_port"] == 0 and p["to_port"] == 65535 for p in sg["ingress"]):
            yield Hit(
                sg["id"],
                f"Security group '{sg['name']}' allows every port from the internet.",
                resource_name=sg["name"],
                region=sg["region"],
            )


@rule(
    id="EC2-004",
    title="Default security group has rules",
    provider=AWS,
    service="ec2",
    severity=Severity.LOW,
    description="Resources launched without an explicit SG land in the default group. It should deny all.",
    remediation="Remove all inbound rules from every VPC's default security group.",
    cis=["5.4"],
    nist=["SC-7", "CM-7"],
    terraform='resource "aws_default_security_group" "default" {\n  vpc_id = "<vpc-id>"\n'
    "  # no ingress / egress blocks = deny all\n}",
)
def default_sg(d: dict[str, Any]) -> Iterator[Hit]:
    for sg in d["security_groups"]:
        if sg["is_default"] and sg["ingress"]:
            yield Hit(
                sg["id"],
                f"Default security group of {sg['vpc_id']} has inbound rules.",
                resource_name=f"default ({sg['vpc_id']})",
                region=sg["region"],
            )


@rule(
    id="EC2-005",
    title="IMDSv2 not enforced",
    provider=AWS,
    service="ec2",
    severity=Severity.MEDIUM,
    description="IMDSv1 is exploitable through SSRF to steal instance role credentials (Capital One, 2019).",
    remediation="Set http_tokens=required on instances and in launch templates.",
    cis=["5.6"],
    nist=["SC-7", "AC-3"],
    terraform='resource "aws_instance" "{resource}" {\n  # ...\n  metadata_options {\n'
    '    http_tokens                 = "required"\n    http_put_response_hop_limit = 1\n  }\n}',
)
def imdsv2(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if i["state"] != "terminated" and not i["imdsv2_required"]:
            yield Hit(
                i["id"],
                f"Instance {i['name'] or i['id']} allows IMDSv1.",
                resource_name=i["name"] or i["id"],
                region=i["region"],
            )


@rule(
    id="EBS-001",
    title="EBS encryption by default disabled",
    provider=AWS,
    service="ec2",
    severity=Severity.MEDIUM,
    description="With default encryption on, every new volume and snapshot is encrypted automatically.",
    remediation="Enable EBS encryption by default in every region.",
    cis=["2.2.1"],
    nist=["SC-28"],
    terraform='resource "aws_ebs_encryption_by_default" "this" {\n  enabled = true\n}',
)
def ebs_default(d: dict[str, Any]) -> Iterator[Hit]:
    for region, enabled in d["ebs_default_encryption"].items():
        if not enabled:
            yield Hit(
                f"ebs-default-encryption/{region}",
                f"EBS encryption by default is off in {region}.",
                resource_name="EBS default encryption",
                region=region,
            )


@rule(
    id="EBS-002",
    title="EBS volume not encrypted",
    provider=AWS,
    service="ec2",
    severity=Severity.MEDIUM,
    description="Unencrypted volumes and their snapshots expose data at rest.",
    remediation="Snapshot, copy with encryption, create a new volume and swap it in.",
    nist=["SC-28"],
)
def ebs_unencrypted(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["volumes"]:
        if not v["encrypted"]:
            yield Hit(
                v["id"],
                f"Volume {v['id']} ({v['size_gb']} GiB) is not encrypted.",
                resource_name=v["name"] or v["id"],
                region=v["region"],
            )


@rule(
    id="EBS-003",
    title="EBS snapshot is public",
    provider=AWS,
    service="ec2",
    severity=Severity.CRITICAL,
    description="Public snapshots can be copied by any AWS account: a full disk image leak.",
    remediation="aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission "
    "--operation-type remove --group-names all. Enable 'Block public access for EBS snapshots'.",
    nist=["AC-3", "AC-21"],
)
def ebs_public_snapshot(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["snapshots"]:
        if s["public"]:
            yield Hit(s["id"], f"Snapshot {s['id']} is publicly restorable.", resource_name=s["id"], region=s["region"])


@rule(
    id="VPC-001",
    title="VPC flow logs disabled",
    provider=AWS,
    service="ec2",
    severity=Severity.MEDIUM,
    description="Flow logs are the network audit trail needed to detect exfiltration and lateral movement.",
    remediation="Enable flow logs (at least REJECT traffic) to CloudWatch Logs or S3.",
    cis=["3.7"],
    nist=["AU-12", "SI-4"],
    terraform='resource "aws_flow_log" "this" {\n  vpc_id               = "{resource}"\n'
    '  traffic_type         = "REJECT"\n  log_destination_type = "s3"\n'
    '  log_destination      = "<log-bucket-arn>"\n}',
)
def flow_logs(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vpcs"]:
        if not v["flow_logs"]:
            yield Hit(v["id"], f"VPC {v['id']} has no flow logs.", resource_name=v["id"], region=v["region"])


# ----------------------------------------------------------------------------- cost waste
@rule(
    id="COST-001",
    title="Unattached EBS volume",
    provider=AWS,
    service="ec2",
    severity=Severity.LOW,
    category=Category.COST,
    description="Detached volumes are billed every month while doing nothing.",
    remediation="Snapshot if needed, then delete the volume.",
)
def unattached_volume(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["volumes"]:
        if not v["attached"]:
            cost = round(v["size_gb"] * EBS_GB_MONTH.get(v["type"], 0.10), 2)
            yield Hit(
                v["id"],
                f"Volume {v['id']} ({v['size_gb']} GiB {v['type']}) is not attached.",
                resource_name=v["name"] or v["id"],
                region=v["region"],
                monthly_savings=cost,
            )


@rule(
    id="COST-002",
    title="gp2 volume can move to gp3",
    provider=AWS,
    service="ec2",
    severity=Severity.INFO,
    category=Category.COST,
    description="gp3 is about 20% cheaper than gp2 and gives a 3,000 IOPS baseline at any size. The change is online.",
    remediation="aws ec2 modify-volume --volume-id <id> --volume-type gp3",
    terraform='resource "aws_ebs_volume" "{resource}" {\n  # ...\n  type = "gp3"\n}',
)
def gp2_to_gp3(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["volumes"]:
        if v["type"] == "gp2":
            yield Hit(
                v["id"],
                f"Volume {v['id']} ({v['size_gb']} GiB) is gp2.",
                resource_name=v["name"] or v["id"],
                region=v["region"],
                monthly_savings=round(v["size_gb"] * 0.02, 2),
            )


@rule(
    id="COST-003",
    title="Idle Elastic IP",
    provider=AWS,
    service="ec2",
    severity=Severity.LOW,
    category=Category.COST,
    description="Every public IPv4 address is billed ($0.005/h), and an unassociated one serves nothing.",
    remediation="Release the Elastic IP if it is not reserved for a planned use.",
)
def idle_eip(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["addresses"]:
        if not a["associated"]:
            yield Hit(
                a["allocation_id"],
                f"Elastic IP {a['ip']} is not associated.",
                resource_name=a["ip"],
                region=a["region"],
                monthly_savings=EIP_IDLE_MONTH,
            )


@rule(
    id="COST-004",
    title="Old EBS snapshot (180+ days)",
    provider=AWS,
    service="ec2",
    severity=Severity.INFO,
    category=Category.COST,
    description="Snapshots pile up silently. Old ones are rarely restored.",
    remediation="Use Data Lifecycle Manager or AWS Backup retention policies; archive or delete old snapshots.",
)
def old_snapshots(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["snapshots"]:
        if s["age_days"] > 180:
            yield Hit(
                s["id"],
                f"Snapshot {s['id']} is {s['age_days']} days old ({s['size_gb']} GiB).",
                resource_name=s["id"],
                region=s["region"],
                monthly_savings=round(s["size_gb"] * SNAPSHOT_GB_MONTH, 2),
            )


@rule(
    id="COST-005",
    title="Previous-generation instance type",
    provider=AWS,
    service="ec2",
    severity=Severity.INFO,
    category=Category.COST,
    description="Current generations (Graviton m7g/c7g/t4g…) deliver better price-performance.",
    remediation="Right-size with Compute Optimizer and move to a current-generation family.",
)
def previous_gen(d: dict[str, Any]) -> Iterator[Hit]:
    for i in d["instances"]:
        if i["state"] == "running" and (i["type"] or "").startswith(PREVIOUS_GEN):
            yield Hit(
                i["id"],
                f"Instance {i['name'] or i['id']} runs previous-generation {i['type']}.",
                resource_name=i["name"] or i["id"],
                region=i["region"],
            )


# ----------------------------------------------------------------------------- Lambda
DEPRECATED_RUNTIMES = {
    "python2.7",
    "python3.6",
    "python3.7",
    "python3.8",
    "nodejs",
    "nodejs4.3",
    "nodejs6.10",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "dotnet5.0",
    "dotnet6",
    "ruby2.5",
    "ruby2.7",
    "java8",
    "go1.x",
    "provided",
}
SECRET_HINTS = ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY")


@rule(
    id="LAMBDA-001",
    title="Lambda uses a deprecated runtime",
    provider=AWS,
    service="lambda",
    severity=Severity.MEDIUM,
    description="Deprecated runtimes get no security patches and eventually can't be updated.",
    remediation="Upgrade to a supported runtime (python3.12+, nodejs20.x+, java21…).",
    nist=["SI-2"],
)
def lambda_runtime(d: dict[str, Any]) -> Iterator[Hit]:
    for f in d["functions"]:
        if f["runtime"] in DEPRECATED_RUNTIMES:
            yield Hit(
                f["arn"],
                f"Function '{f['name']}' runs deprecated {f['runtime']}.",
                resource_name=f["name"],
                region=f["region"],
            )


@rule(
    id="LAMBDA-002",
    title="Lambda is publicly invocable",
    provider=AWS,
    service="lambda",
    severity=Severity.HIGH,
    description="A function URL with AuthType NONE or a '*' resource policy can be called by anyone.",
    remediation="Use AWS_IAM auth for function URLs or put the function behind API Gateway with auth.",
    nist=["AC-3", "SC-7"],
)
def lambda_public(d: dict[str, Any]) -> Iterator[Hit]:
    for f in d["functions"]:
        if f["url_auth_none"] or f["public_policy"]:
            how = "function URL without auth" if f["url_auth_none"] else "public resource policy"
            yield Hit(
                f["arn"],
                f"Function '{f['name']}' is publicly invocable ({how}).",
                resource_name=f["name"],
                region=f["region"],
            )


@rule(
    id="LAMBDA-003",
    title="Possible secret in Lambda environment",
    provider=AWS,
    service="lambda",
    severity=Severity.MEDIUM,
    description="Environment variables are visible to anyone with lambda:GetFunctionConfiguration.",
    remediation="Store secrets in Secrets Manager or SSM Parameter Store and fetch them at runtime.",
    nist=["IA-5(7)", "SC-28"],
)
def lambda_secrets(d: dict[str, Any]) -> Iterator[Hit]:
    for f in d["functions"]:
        names = [n for n in f.get("env_var_names", []) if any(h in n.upper() for h in SECRET_HINTS)]
        if names:
            yield Hit(
                f["arn"],
                f"Function '{f['name']}' has secret-looking env vars: {', '.join(names)}.",
                resource_name=f["name"],
                region=f["region"],
                details={"variables": names},
            )
