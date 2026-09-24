"""
rules_engine/cloudtrail_rules.py

Règles de sécurité appliquées aux trails CloudTrail lus par
aws_reader/cloudtrail_scanner.py. Fonctions pures, aucun appel AWS.

CT-001 est une règle d'ABSENCE : elle se déclenche quand il n'y a aucun trail.
"""


def check_no_trail(trails):
    """Règle CT-001 : aucun trail CloudTrail sur le compte (absence)."""
    if trails:
        return []

    return [{
        "rule_id": "CT-001",
        "severity": "HIGH",
        "resource": "compte AWS",
        "message": "Aucun trail CloudTrail n'est configuré. Les actions "
                   "administratives et les accès aux ressources ne sont nulle "
                   "part journalisés : en cas d'intrusion, aucune preuve "
                   "d'audit ne sera disponible.",
    }]


def check_not_multi_region(trails):
    """Règle CT-002 : trail présent mais ne couvrant pas toutes les régions."""
    findings = []
    for trail in trails:
        if not trail["multi_region"]:
            findings.append({
                "rule_id": "CT-002",
                "severity": "MEDIUM",
                "resource": trail["name"],
                "message": f"Le trail '{trail['name']}' n'est pas multi-région. "
                           f"Une action malveillante dans une autre région "
                           f"ne sera pas journalisée.",
            })
    return findings


def check_log_validation_disabled(trails):
    """Règle CT-003 : la validation des fichiers de logs est désactivée."""
    findings = []
    for trail in trails:
        if not trail["log_validation"]:
            findings.append({
                "rule_id": "CT-003",
                "severity": "LOW",
                "resource": trail["name"],
                "message": f"Le trail '{trail['name']}' n'a pas la validation "
                           f"des logs activée : un attaquant ayant accès aux "
                           f"logs pourrait les modifier sans être détecté.",
            })
    return findings


def check_trail_not_logging(trails):
    """Règle CT-004 : trail existant mais inactif."""
    findings = []
    for trail in trails:
        if not trail["is_logging"]:
            findings.append({
                "rule_id": "CT-004",
                "severity": "MEDIUM",
                "resource": trail["name"],
                "message": f"Le trail '{trail['name']}' existe mais n'enregistre "
                           f"plus d'événements (IsLogging = False).",
            })
    return findings


def run_all_cloudtrail_rules(trails):
    """Point d'entrée principal : lance toutes les règles CloudTrail."""
    findings = []
    findings += check_no_trail(trails)
    findings += check_not_multi_region(trails)
    findings += check_log_validation_disabled(trails)
    findings += check_trail_not_logging(trails)
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.cloudtrail_scanner import list_trails

    trails = list_trails()
    findings = run_all_cloudtrail_rules(trails)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")