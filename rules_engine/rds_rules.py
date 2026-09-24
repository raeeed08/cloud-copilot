"""
rules_engine/rds_rules.py

Règles de sécurité appliquées aux données RDS lues par aws_reader/rds_scanner.py.
Fonctions pures, aucun appel AWS.

Note : le scanner renvoie un dict {"instances": [...], "snapshots": [...]},
donc la fonction d'entrée prend ce dict, pas une liste simple.
"""


def check_public_instances(instances):
    """Règle RDS-001 : instance accessible depuis Internet."""
    findings = []
    for instance in instances:
        if instance["publicly_accessible"]:
            findings.append({
                "rule_id": "RDS-001",
                "severity": "HIGH",
                "resource": instance["identifier"],
                "message": f"L'instance RDS '{instance['identifier']}' est "
                           f"accessible publiquement depuis Internet. Une base "
                           f"de données exposée est une cible directe de force "
                           f"brute : activez le VPC privé.",
            })
    return findings


def check_unencrypted_instances(instances):
    """Règle RDS-002 : instance non chiffrée au repos."""
    findings = []
    for instance in instances:
        if not instance["storage_encrypted"]:
            findings.append({
                "rule_id": "RDS-002",
                "severity": "MEDIUM",
                "resource": instance["identifier"],
                "message": f"L'instance RDS '{instance['identifier']}' n'est pas "
                           f"chiffrée au repos : si un volume est volé ou "
                           f"dupliqué, les données sont lisibles en clair.",
            })
    return findings


def check_public_snapshots(snapshots):
    """Règle RDS-003 : snapshot partagé publiquement (fuite de données)."""
    findings = []
    for snapshot in snapshots:
        if snapshot["is_public"]:
            findings.append({
                "rule_id": "RDS-003",
                "severity": "HIGH",
                "resource": snapshot["identifier"],
                "message": f"Le snapshot RDS '{snapshot['identifier']}' est "
                           f"partagé publiquement : n'importe qui peut le "
                           f"télécharger et restaurer une copie complète de "
                           f"la base. C'est une fuite de données en cours.",
            })
    return findings


def run_all_rds_rules(rds_data):
    """Point d'entrée principal : traite le dict du scanner (instances + snapshots)."""
    findings = []
    findings += check_public_instances(rds_data["instances"])
    findings += check_unencrypted_instances(rds_data["instances"])
    findings += check_public_snapshots(rds_data["snapshots"])
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.rds_scanner import list_db_instances, list_db_snapshots

    rds_data = {
        "instances": list_db_instances(),
        "snapshots": list_db_snapshots(),
    }
    findings = run_all_rds_rules(rds_data)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")