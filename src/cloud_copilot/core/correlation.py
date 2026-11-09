"""
Attack-path correlation ("toxic combinations").

A single finding is a weakness; several findings on connected resources are a *breach path*. This module
walks the raw, normalised scanner data of one account and chains findings together, the way an attacker would,
and maps each step to MITRE ATT&CK techniques. Each scenario names the cheapest action that breaks the chain.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from typing import Any

from cloud_copilot.models import Finding, Severity
from cloud_copilot.providers.aws.rules.compute import ADMIN_PORTS, DATA_PORTS, SECRET_HINTS, exposed_ports


@dataclass
class Step:
    title: str
    detail: str
    technique: str | None = None  # MITRE ATT&CK id
    rule_id: str | None = None


@dataclass
class Scenario:
    id: str
    title: str
    severity: str
    provider: str
    account: str | None
    resource: str
    summary: str
    impact: str
    steps: list[Step]
    break_first: str
    break_rule: str | None
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Index:
    """Lookup of findings by (rule, resource_id) and by rule, for one account."""

    def __init__(self, findings: list[Finding]) -> None:
        self.by_key = {(f.rule_id, f.resource_id): f for f in findings if not f.suppressed}
        self.by_rule: dict[str, list[Finding]] = {}
        for f in findings:
            if not f.suppressed:
                self.by_rule.setdefault(f.rule_id, []).append(f)

    def get(self, rule: str, resource: str) -> Finding | None:
        return self.by_key.get((rule, resource))

    def ids(self, *pairs: tuple[str, str]) -> list[str]:
        return [f.id for p in pairs if (f := self.get(*p))]


def _sid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


# ----------------------------------------------------------------------------- AWS
def aws_exposed_instance(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    ec2 = data.get("ec2")
    if not ec2:
        return
    sgs = {sg["id"]: sg for sg in ec2.get("security_groups", [])}
    for inst in ec2.get("instances", []):
        if inst.get("state") != "running" or not inst.get("public_ip"):
            continue
        groups = [sgs[g] for g in inst.get("security_groups", []) if g in sgs]
        admin = sorted({p for g in groups for p in exposed_ports(g, ADMIN_PORTS)})
        if not admin:
            continue
        name = inst.get("name") or inst["id"]
        imds_v1 = not inst.get("imdsv2_required", True)
        steps = [
            Step(
                "Reach the host",
                f"{name} has public IP {inst['public_ip']} with {', '.join(admin)} open to 0.0.0.0/0.",
                "T1190",
                "EC2-001",
            ),
            Step(
                "Get a shell",
                "Password spraying / credential stuffing on the admin port, or an unpatched service exploit.",
                "T1110",
            ),
        ]
        severity = Severity.HIGH
        impact = "Full control of the instance and anything it can reach on the network."
        if imds_v1 and inst.get("instance_profile"):
            steps.append(
                Step(
                    "Steal cloud credentials",
                    "IMDSv1 is enabled: one HTTP call to "
                    "169.254.169.254 returns the instance role's temporary AWS keys.",
                    "T1552.005",
                    "EC2-005",
                )
            )
            steps.append(
                Step(
                    "Move into the AWS account",
                    "Use the role credentials from anywhere to call AWS APIs with the role's permissions.",
                    "T1078.004",
                )
            )
            severity = Severity.CRITICAL
            impact = "An internet attacker turns a server compromise into AWS API access with the instance role."
        fids = idx.ids(("EC2-005", inst["id"])) + [f.id for g in groups if (f := idx.get("EC2-001", g["id"]))]
        yield Scenario(
            id=_sid("exposed-instance", inst["id"]),
            title=f"Internet-exposed server {name} → cloud credential theft"
            if severity is Severity.CRITICAL
            else f"Internet-exposed server {name}",
            severity=severity.value,
            provider="aws",
            account=account,
            resource=name,
            summary=f"{name} is reachable from the whole internet on {', '.join(admin)}"
            + (" and still allows IMDSv1, so a foothold leaks its IAM role credentials." if imds_v1 else "."),
            impact=impact,
            steps=steps,
            break_first="Close the admin port to 0.0.0.0/0 (use SSM Session Manager), then require IMDSv2.",
            break_rule="EC2-001",
            finding_ids=fids,
        )


def aws_public_database(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    rds, ec2 = data.get("rds"), data.get("ec2")
    if not rds:
        return
    sgs = {sg["id"]: sg for sg in (ec2 or {}).get("security_groups", [])}
    for db in rds.get("instances", []):
        if not db.get("public"):
            continue
        groups = [sgs[g] for g in db.get("security_groups", []) if g in sgs]
        ports = sorted({p for g in groups for p in exposed_ports(g, DATA_PORTS)})
        if groups and not ports:
            continue  # public endpoint but SG closes it: weakness, not a path
        steps = [
            Step(
                "Find the database",
                f"RDS '{db['id']}' has a public endpoint"
                + (f" and {', '.join(ports)} is open to the internet." if ports else "."),
                "T1190",
                "RDS-001",
            ),
            Step("Brute-force the login", "Database logins have no MFA and are scanned continuously.", "T1110"),
        ]
        if not db.get("encrypted"):
            steps.append(
                Step("Exfiltrate", "Storage and snapshots are unencrypted, so copies are readable.", "T1530", "RDS-002")
            )
        if db.get("backup_retention_days", 7) < 7:
            steps.append(
                Step(
                    "Destroy / ransom",
                    f"Only {db['backup_retention_days']} day(s) of backups: a "
                    "wipe or ransomware note is hard to recover from.",
                    "T1485",
                    "RDS-004",
                )
            )
        fids = idx.ids(("RDS-001", db["id"]), ("RDS-002", db["id"]), ("RDS-004", db["id"])) + [
            f.id for g in groups if (f := idx.get("EC2-002", g["id"]))
        ]
        yield Scenario(
            id=_sid("public-db", db["id"]),
            title=f"Database {db['id']} exposed to the internet",
            severity=Severity.CRITICAL.value,
            provider="aws",
            account=account,
            resource=db["id"],
            summary=f"{db['engine']} database '{db['id']}' accepts connections from anywhere; weak backup and "
            "encryption settings make a breach both likely and costly.",
            impact="Theft or destruction of the data in the database.",
            steps=steps,
            break_first="Set publicly_accessible=false and restrict the security group to the app tier.",
            break_rule="RDS-001",
            finding_ids=fids,
        )


def aws_admin_takeover(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    iam = data.get("iam")
    if not iam:
        return
    for u in iam.get("users", []):
        admin = "AdministratorAccess" in u.get("attached_policies", [])
        if not (admin and u.get("console_access") and not u.get("mfa_enabled")):
            continue
        old_keys = [k for k in u.get("access_keys", []) if k["status"] == "Active" and (k["age_days"] or 0) > 90]
        steps = [
            Step(
                "Phish or reuse the password",
                f"'{u['name']}' signs in to the console with a password only, no MFA.",
                "T1078.004",
                "IAM-004",
            ),
            Step(
                "Own the account",
                "The user has AdministratorAccess: create backdoor users, disable logging, read every bucket.",
                "T1098",
                "IAM-009",
            ),
        ]
        if old_keys:
            steps.insert(
                1,
                Step(
                    "…or use a leaked key",
                    f"An access key {old_keys[0]['age_days']} days old is "
                    "still active: old keys end up in repos, laptops and CI logs.",
                    "T1552",
                    "IAM-005",
                ),
            )
        yield Scenario(
            id=_sid("admin-takeover", u["arn"]),
            title=f"Account takeover through admin user '{u['name']}'",
            severity=Severity.CRITICAL.value,
            provider="aws",
            account=account,
            resource=u["name"],
            summary=f"A single stolen password for '{u['name']}' gives full administrator control of the account.",
            impact="Complete account compromise: data, infrastructure, billing.",
            steps=steps,
            break_first="Enforce MFA for this user today; then remove AdministratorAccess in favour of a role.",
            break_rule="IAM-004",
            finding_ids=idx.ids(("IAM-004", u["arn"]), (("IAM-009", f"{u['arn']}/AdministratorAccess")))
            + [f.id for k in old_keys if (f := idx.get("IAM-005", f"{u['arn']}/{k['id']}"))],
        )


def aws_blind_spot(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    ct, det = data.get("cloudtrail"), data.get("detective")
    if ct is None or det is None:
        return
    no_trail = bool(idx.by_rule.get("CT-001"))
    dark = [r["region"] for r in det.get("regions", []) if not r.get("guardduty")]
    if not (no_trail and dark):
        return
    steps = [
        Step(
            "Operate in an unwatched region",
            f"GuardDuty is off in {', '.join(dark)}: crypto-mining or recon there raises no alert.",
            "T1535",
            "GD-001",
        ),
        Step(
            "Leave no audit trail",
            "No multi-region CloudTrail: API calls are not recorded, so the intrusion cannot be reconstructed.",
            "T1562.008",
            "CT-001",
        ),
    ]
    fids = [f.id for f in idx.by_rule.get("CT-001", [])] + [f.id for f in idx.by_rule.get("GD-001", [])]
    yield Scenario(
        id=_sid("blind-spot", account or ""),
        title="Detection blind spot: an intruder would go unnoticed",
        severity=Severity.HIGH.value,
        provider="aws",
        account=account,
        resource="account",
        summary="Missing audit logging combined with regions without threat detection means a compromise would "
        "be neither detected nor investigable.",
        impact="Undetected long-lived compromise; no evidence for incident response or regulators.",
        steps=steps,
        break_first="Create one multi-region CloudTrail and enable GuardDuty in every region.",
        break_rule="CT-001",
        finding_ids=fids,
    )


def aws_public_function_secrets(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    lam = data.get("lambda")
    if not lam:
        return
    for fn in lam.get("functions", []):
        secrets = [n for n in fn.get("env_var_names", []) if any(h in n.upper() for h in SECRET_HINTS)]
        if not ((fn.get("url_auth_none") or fn.get("public_policy")) and secrets):
            continue
        yield Scenario(
            id=_sid("public-fn", fn["arn"]),
            title=f"Public function '{fn['name']}' holds secrets",
            severity=Severity.HIGH.value,
            provider="aws",
            account=account,
            resource=fn["name"],
            summary=f"Anyone can invoke '{fn['name']}', and its environment contains {', '.join(secrets)}. "
            "A code-injection or debug bug leaks the secret.",
            impact="Leak of third-party credentials (payments, APIs) and abuse billed to you.",
            steps=[
                Step("Invoke without auth", "Function URL with AuthType NONE.", "T1190", "LAMBDA-002"),
                Step(
                    "Read the environment", f"Secrets in plain env vars: {', '.join(secrets)}.", "T1552", "LAMBDA-003"
                ),
            ],
            break_first="Switch the function URL to AWS_IAM auth and move the secret to Secrets Manager.",
            break_rule="LAMBDA-002",
            finding_ids=idx.ids(("LAMBDA-002", fn["arn"]), ("LAMBDA-003", fn["arn"])),
        )


# ----------------------------------------------------------------------------- Azure
def azure_exposed_vm(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    compute = data.get("compute")
    if not (data.get("network") and compute):
        return
    nsg_findings = idx.by_rule.get("AZ-NSG-001", [])
    for vm in compute.get("vms", []):
        if not vm.get("password_auth"):
            continue
        rg = vm.get("resource_group")
        open_nsgs = [f for f in nsg_findings if f"/resourceGroups/{rg}/" in f.resource_id]
        if not open_nsgs:
            continue
        ports = sorted({p for f in open_nsgs for p in f.details.get("ports", [])})
        names = ", ".join(f.resource_name for f in open_nsgs)
        yield Scenario(
            id=_sid("az-vm", vm["id"]),
            title=f"VM {vm['name']} brute-forceable from the internet",
            severity=Severity.CRITICAL.value,
            provider="azure",
            account=account,
            resource=vm["name"],
            summary=f"NSG(s) {names} open {', '.join(ports)} to the internet in the resource group of "
            f"'{vm['name']}', which accepts password logins.",
            impact="Remote takeover of the VM and a foothold in the virtual network.",
            steps=[
                Step("Reach the VM", "Admin port open to Internet/any.", "T1190", "AZ-NSG-001"),
                Step("Guess the password", "Password authentication is enabled.", "T1110", "AZ-VM-001"),
            ],
            break_first="Remove the internet rule and use Azure Bastion or Just-In-Time access.",
            break_rule="AZ-NSG-001",
            finding_ids=[f.id for f in open_nsgs] + idx.ids(("AZ-VM-001", vm["id"])),
        )


def azure_open_storage(data: dict[str, Any], idx: _Index, account: str | None) -> Iterator[Scenario]:
    st = data.get("storage")
    if not st:
        return
    for a in st.get("accounts", []):
        if not (a.get("allow_blob_public_access") and a.get("network_default_action") == "Allow"):
            continue
        steps = [
            Step(
                "Enumerate containers",
                "Anonymous blob access is allowed and the account accepts traffic from any network.",
                "T1530",
                "AZ-STOR-001",
            )
        ]
        if a.get("shared_key_access"):
            steps.append(
                Step(
                    "Reuse a leaked account key",
                    "Shared-key auth is on: one leaked key = full data access, invisible to Entra ID.",
                    "T1552",
                    "AZ-STOR-004",
                )
            )
        yield Scenario(
            id=_sid("az-storage", a["id"]),
            title=f"Storage account {a['name']} open to the internet",
            severity=Severity.HIGH.value,
            provider="azure",
            account=account,
            resource=a["name"],
            summary=f"'{a['name']}' allows anonymous containers and accepts traffic from all networks.",
            impact="Data exposure (logs, exports, backups) to anyone who finds the URL.",
            steps=steps,
            break_first="Disable 'Allow Blob anonymous access' and set the network default action to Deny.",
            break_rule="AZ-STOR-001",
            finding_ids=idx.ids(("AZ-STOR-001", a["id"]), ("AZ-STOR-004", a["id"]), ("AZ-STOR-005", a["id"])),
        )


CORRELATORS: dict[str, list[Callable[[dict[str, Any], _Index, str | None], Iterator[Scenario]]]] = {
    "aws": [aws_exposed_instance, aws_public_database, aws_admin_takeover, aws_blind_spot, aws_public_function_secrets],
    "azure": [azure_exposed_vm, azure_open_storage],
}


def correlate(raw: dict[str, dict[str, Any]], findings: list[Finding]) -> list[dict[str, Any]]:
    """raw = {"aws:<account>": {service: data}}; returns scenarios sorted by severity."""
    out: list[Scenario] = []
    for key, services in raw.items():
        provider, _, account = key.partition(":")
        acct = None if account == "default" else account
        idx = _Index([f for f in findings if f.provider.value == provider and (acct is None or f.account == acct)])
        for fn in CORRELATORS.get(provider, []):
            try:
                out.extend(fn(services, idx, acct))
            except (KeyError, TypeError, ValueError):
                continue  # partial data: skip this correlation rather than fail the scan
    out.sort(key=lambda s: Severity(s.severity).rank)
    return [s.to_dict() for s in out]
