"""
Remediation strategy: turn findings + attack paths into a phased, prioritised plan.

Prioritisation (what a senior cloud security engineer would do):
1. Break active attack paths first, cheapest link first (one change can kill a whole chain).
2. Then remaining CRITICAL exposure, then identity & data protection, then detection & resilience,
   then hygiene. Cost savings run in parallel (different owners, no security trade-off).
3. Inside a phase: biggest posture gain per unit of effort first.
4. Finish with *guardrails* so the same misconfiguration cannot come back (shift-left + preventive policy).

The plan is deterministic and explainable; the LLM only narrates it.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cloud_copilot.core.engine import score
from cloud_copilot.core.registry import RULES
from cloud_copilot.models import Category, Finding, Severity

EFFORT_POINTS = {"S": 1, "M": 2, "L": 4}
LARGE = {
    "RDS-002",
    "EBS-002",
    "IAM-008",
    "IAM-009",
    "AZ-KV-002",
    "EKS-001",
    "AZ-AKS-001",
    "AZ-AKS-002",
    "LAMBDA-001",
    "RDS-007",
    "COST-005",
}
MEDIUM = {
    "EC2-001",
    "EC2-002",
    "EC2-003",
    "RDS-001",
    "CT-001",
    "VPC-001",
    "IAM-004",
    "IAM-005",
    "IAM-006",
    "AZ-NSG-001",
    "AZ-NSG-002",
    "AZ-NSG-003",
    "AZ-SQL-001",
    "AZ-SQL-002",
    "AZ-STOR-004",
    "AZ-STOR-005",
    "AZ-KV-003",
    "S3-004",
    "LAMBDA-003",
    "EC2-005",
    "ELB-002",
    "AZ-MON-002",
    "EKS-002",
    "GD-001",
    "CFG-001",
    "AZ-ACR-002",
}
IDENTITY_DATA_SERVICES = {
    "iam",
    "accessanalyzer",
    "s3",
    "rds",
    "kms",
    "secretsmanager",
    "dynamodb",
    "messaging",
    "ecr",
    "lambda",
    "storage",
    "keyvault",
    "sql",
    "acr",
}

PHASES = [
    (
        "now",
        "Stop the bleeding",
        "Today",
        "Break every attack path and remove direct internet exposure. Small, reversible changes with the "
        "biggest risk reduction.",
    ),
    (
        "week",
        "Lock down identity & data",
        "This week",
        "Make stolen credentials less likely and less useful; protect data at rest and in transit.",
    ),
    (
        "month",
        "Detection & resilience",
        "This month",
        "See attacks when they happen, keep the evidence, and be able to recover.",
    ),
    ("hygiene", "Hardening & hygiene", "This quarter", "Low-risk improvements that reduce attack surface over time."),
    ("cost", "Save money", "In parallel", "Remove waste. No security trade-off, usually a different owner."),
]

GUARDRAILS: list[dict[str, Any]] = [
    {
        "title": "Block public S3 at the organization level",
        "rules": ["S3-001", "S3-002", "S3-003"],
        "why": "Account-level Block Public Access plus an SCP means no one can make a bucket public again.",
        "how": '{\n  "Effect": "Deny",\n  "Action": ["s3:PutAccountPublicAccessBlock"],\n  "Resource": "*",\n'
        '  "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass"}}\n}',
        "kind": "AWS SCP",
    },
    {
        "title": "Require IMDSv2 on every new instance",
        "rules": ["EC2-005"],
        "why": "Prevents SSRF-based credential theft by construction.",
        "how": '{\n  "Effect": "Deny",\n  "Action": "ec2:RunInstances",\n  "Resource": "arn:aws:ec2:*:*:instance/*",\n'
        '  "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}\n}',
        "kind": "AWS SCP",
    },
    {
        "title": "Make logging and threat detection tamper-proof",
        "rules": ["CT-001", "CT-002", "CT-003", "GD-001", "CFG-001", "SH-001"],
        "why": "Attackers disable logging first. Deny it for everyone except a break-glass role.",
        "how": '{\n  "Effect": "Deny",\n  "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail",\n'
        '             "guardduty:DeleteDetector", "config:StopConfigurationRecorder"],\n  "Resource": "*"\n}',
        "kind": "AWS SCP",
    },
    {
        "title": "Stop world-open admin and database ports in code review",
        "rules": ["EC2-001", "EC2-002", "EC2-003", "AZ-NSG-001", "AZ-NSG-002", "AZ-NSG-003"],
        "why": "Catch the misconfiguration in the pull request, before it reaches the cloud.",
        "how": "# CI step on every Terraform PR\ncheckov -d infra/ --check CKV_AWS_24,CKV_AWS_25 --compact\n"
        "trivy config --severity HIGH,CRITICAL infra/",
        "kind": "Policy as code (CI)",
    },
    {
        "title": "Move humans to SSO, stop creating IAM users",
        "rules": ["IAM-004", "IAM-005", "IAM-006", "IAM-007", "IAM-008", "IAM-009"],
        "why": "IAM Identity Center gives MFA, short-lived credentials and central off-boarding.",
        "how": '{\n  "Effect": "Deny",\n  "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"],\n'
        '  "Resource": "*",\n  "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass"}}\n}',
        "kind": "AWS SCP",
    },
    {
        "title": "Encrypt by default",
        "rules": ["EBS-001", "EBS-002", "RDS-002", "S3-007"],
        "why": "Default encryption removes the decision from every engineer.",
        "how": '{\n  "Effect": "Deny",\n  "Action": "rds:CreateDBInstance",\n  "Resource": "*",\n'
        '  "Condition": {"Bool": {"rds:StorageEncrypted": "false"}}\n}',
        "kind": "AWS SCP",
    },
    {
        "title": "Deny public storage accounts with Azure Policy",
        "rules": ["AZ-STOR-001", "AZ-STOR-002", "AZ-STOR-003", "AZ-STOR-005"],
        "why": "Built-in policies with the Deny effect block non-compliant storage at creation time.",
        "how": "az policy assignment create --name deny-public-storage \\\n"
        '  --policy "Storage account public access should be disallowed" --params \'{"effect":{"value":"Deny"}}\'',
        "kind": "Azure Policy",
    },
    {
        "title": "Deploy diagnostics and Defender plans automatically",
        "rules": ["AZ-MON-001", "AZ-MON-002", "AZ-DEF-001", "AZ-SQL-003"],
        "why": "DeployIfNotExists policies keep every subscription monitored, including new ones.",
        "how": "Assign the 'Microsoft Cloud Security Benchmark' initiative and the built-in "
        "'Configure Azure Defender to be enabled' policies at the management group.",
        "kind": "Azure Policy",
    },
]
CONTINUOUS = {
    "title": "Scan continuously and fail the pipeline on new CRITICAL findings",
    "rules": [],
    "why": "Drift and click-ops happen. A scheduled scan closes the loop and keeps the score honest.",
    "how": "cloud-copilot scan --fail-on CRITICAL   # nightly GitHub Action or Kubernetes CronJob",
    "kind": "Continuous posture",
}


def effort(rule_id: str) -> str:
    return "L" if rule_id in LARGE else "M" if rule_id in MEDIUM else "S"


def _phase(rule_id: str, sev: Severity, breaks: bool) -> str:
    info = RULES[rule_id].info
    if info.category is Category.COST:
        return "cost"
    if breaks or sev is Severity.CRITICAL:
        return "now"
    if sev is Severity.HIGH or (sev is Severity.MEDIUM and info.service in IDENTITY_DATA_SERVICES):
        return "week"
    if sev is Severity.MEDIUM or info.category is Category.RELIABILITY:
        return "month"
    return "hygiene"


def build_plan(
    findings: list[Finding],
    scenarios: list[dict[str, Any]],
    evaluated_rules: list[str],
    resolved: list[str] | None = None,
) -> dict[str, Any]:
    active = [f for f in findings if not f.suppressed and f.rule_id in RULES]
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in active:
        by_rule[f.rule_id].append(f)

    breaking: dict[str, list[str]] = defaultdict(list)
    for s in scenarios:
        if s.get("break_rule"):
            breaking[s["break_rule"]].append(s["title"])

    evaluated = set(evaluated_rules)
    current, _, _ = score(active, evaluated)
    scorable = [
        r
        for r in evaluated
        if r in RULES and RULES[r].info.category is not Category.COST and RULES[r].info.severity is not Severity.INFO
    ]
    total_weight = sum(RULES[r].info.severity.weight for r in scorable) or 1
    phases: dict[str, list[dict[str, Any]]] = {p[0]: [] for p in PHASES}
    for rule_id, items in by_rule.items():
        info = RULES[rule_id].info
        sev = min((f.severity for f in items), key=lambda s: s.rank)
        # exact share of the weighted score this control is worth once it passes
        gain = round(100 * info.severity.weight / total_weight, 1) if rule_id in scorable else 0.0
        eff = effort(rule_id)
        savings = round(sum(f.estimated_monthly_savings or 0 for f in items), 2)
        phases[_phase(rule_id, sev, rule_id in breaking)].append(
            {
                "rule_id": rule_id,
                "title": info.title,
                "severity": sev.value,
                "category": info.category.value,
                "provider": info.provider.value,
                "service": info.service,
                "effort": eff,
                "score_gain": gain,
                "monthly_savings": savings or None,
                "breaks": breaking.get(rule_id, []),
                "why": info.description,
                "steps": info.remediation,
                "terraform": items[0].terraform,
                "verify": f"Re-scan: rule {rule_id} should pass on all {len(items)} resource(s).",
                "compliance": info.compliance,
                "resources": [
                    {
                        "finding_id": f.id,
                        "name": f.resource_name,
                        "region": f.region,
                        "account": f.account,
                        "message": f.message,
                        "console_url": f.console_url,
                    }
                    for f in items
                ],
            }
        )

    def priority(a: dict[str, Any]) -> tuple[Any, ...]:
        value = a["score_gain"] + 15 * len(a["breaks"]) + (a["monthly_savings"] or 0) / 10
        return (-len(a["breaks"]), Severity(a["severity"]).rank, -value / EFFORT_POINTS[a["effort"]], a["rule_id"])

    failed_rules = set(by_rule)
    guardrails = [g for g in GUARDRAILS if failed_rules & set(g["rules"])] + [CONTINUOUS]
    out_phases = []
    for pid, title, horizon, goal in PHASES:
        actions = sorted(phases[pid], key=priority)
        if not actions:
            continue
        out_phases.append(
            {
                "id": pid,
                "title": title,
                "horizon": horizon,
                "goal": goal,
                "actions": actions,
                "findings": sum(len(a["resources"]) for a in actions),
                "score_gain": round(sum(a["score_gain"] for a in actions), 1),
                "monthly_savings": round(sum(a["monthly_savings"] or 0 for a in actions), 2),
            }
        )
    target, _, _ = score([f for f in active if RULES[f.rule_id].info.category is Category.COST], evaluated)
    return {
        "current_score": current,
        "target_score": target,
        "actions": sum(len(p["actions"]) for p in out_phases),
        "findings": len(active),
        "monthly_savings": round(sum(f.estimated_monthly_savings or 0 for f in active), 2),
        "scenarios_open": len(scenarios),
        "resolved_since_last_scan": len(resolved or []),
        "phases": out_phases,
        "guardrails": guardrails,
    }
