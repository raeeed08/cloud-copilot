"""
rules_engine/ec2_rules.py

Règles de sécurité appliquées aux security groups EC2 lus par
aws_reader/ec2_scanner.py. Même principe : fonctions pures, aucun appel AWS.
"""


def check_open_to_world(security_groups):
    """Règle EC2-001 : security group autorisant le trafic depuis 0.0.0.0/0."""
    findings = []
    for sg in security_groups:
        if sg["open_to_world"]:
            findings.append({
                "rule_id": "EC2-001",
                "severity": "HIGH",
                "resource": f"{sg['name']} ({sg['id']})",
                "message": f"Le security group '{sg['name']}' autorise le trafic "
                           f"entrant depuis le monde entier (0.0.0.0/0). N'importe "
                           f"qui peut tenter de se connecter aux instances associées.",
            })
    return findings


def check_ssh_rdp_open(security_groups):
    """Règle EC2-002 : SSH (22) ou RDP (3389) ouvert au monde entier."""
    findings = []
    for sg in security_groups:
        if sg["ssh_rdp_open_to_world"]:
            findings.append({
                "rule_id": "EC2-002",
                "severity": "HIGH",
                "resource": f"{sg['name']} ({sg['id']})",
                "message": f"Le security group '{sg['name']}' expose SSH (22) ou "
                           f"RDP (3389) au monde entier. C'est une invitation à la "
                           f"force brute : restreignez à vos IP de confiance.",
            })
    return findings


def run_all_ec2_rules(security_groups):
    """Point d'entrée principal : lance toutes les règles EC2."""
    findings = []
    findings += check_open_to_world(security_groups)
    findings += check_ssh_rdp_open(security_groups)
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.ec2_scanner import list_security_groups

    sgs = list_security_groups()
    findings = run_all_ec2_rules(sgs)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")