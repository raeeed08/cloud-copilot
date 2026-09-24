"""
rules_engine/azure_rules.py

Règles de sécurité appliquées aux données Azure lues par
azure_reader/azure_scanner.py. Fonctions pures, aucun appel Azure.

Le scanner renvoie un dict {"storage": [...], "nsg": [...], "monitoring": {...}},
donc la fonction d'entrée prend ce dict (comme rds_rules pour AWS).
"""


def check_storage_public(storage):
    """Règle AZ-STOR-001 : storage account à accès public autorisé."""
    findings = []
    for sa in storage:
        if sa["public_access"]:
            findings.append({
                "rule_id": "AZ-STOR-001",
                "severity": "HIGH",
                "resource": f"{sa['name']} ({sa['resource_group']})",
                "message": f"Le storage account '{sa['name']}' autorise un accès "
                           f"public. Les données peuvent être exposées à Internet.",
            })
    return findings


def check_storage_https(storage):
    """Règle AZ-STOR-002 : trafic HTTPS non forcé."""
    findings = []
    for sa in storage:
        if not sa["https_only"]:
            findings.append({
                "rule_id": "AZ-STOR-002",
                "severity": "MEDIUM",
                "resource": f"{sa['name']} ({sa['resource_group']})",
                "message": f"Le storage account '{sa['name']}' n'impose pas le "
                           f"trafic HTTPS : les données peuvent transiter en clair.",
            })
    return findings


def check_storage_shared_key(storage):
    """Règle AZ-STOR-003 : authentification par clé partagée activée."""
    findings = []
    for sa in storage:
        if sa["key_auth_enabled"]:
            findings.append({
                "rule_id": "AZ-STOR-003",
                "severity": "LOW",
                "resource": f"{sa['name']} ({sa['resource_group']})",
                "message": f"Le storage account '{sa['name']}' autorise la clé "
                           f"partagée. Préférez l'authentification Entra ID (moins de secrets).",
            })
    return findings


def check_nsg_open_internet(nsg):
    """Règle AZ-NSG-001 : NSG ouvert vers Internet."""
    findings = []
    for g in nsg:
        if g["open_to_internet"]:
            findings.append({
                "rule_id": "AZ-NSG-001",
                "severity": "HIGH",
                "resource": f"{g['name']} ({g['resource_group']})",
                "message": f"Le NSG '{g['name']}' autorise du trafic entrant depuis "
                           f"Internet (0.0.0.0/0 / tag 'Internet').",
            })
    return findings


def check_nsg_ssh_rdp(nsg):
    """Règle AZ-NSG-002 : SSH/RDP ouvert vers Internet."""
    findings = []
    for g in nsg:
        if g["ssh_rdp_open_to_internet"]:
            findings.append({
                "rule_id": "AZ-NSG-002",
                "severity": "HIGH",
                "resource": f"{g['name']} ({g['resource_group']})",
                "message": f"Le NSG '{g['name']}' expose SSH (22) ou RDP (3389) à "
                           f"Internet : risque de force brute.",
            })
    return findings


def check_activity_log(monitoring):
    """Règle AZ-ACT-001 : pas de activity log (équivalent CloudTrail absent)."""
    if monitoring.get("activity_log_configured"):
        return []
    return [{
        "rule_id": "AZ-ACT-001",
        "severity": "HIGH",
        "resource": "abonnement Azure",
        "message": "Aucun log profile (activity log) configuré au niveau de "
                   "l'abonnement. Les actions administratives ne sont pas auditées.",
    }]


def check_diagnostic_settings(monitoring):
    """Règle AZ-ACT-002 : pas de diagnostic settings d'abonnement."""
    if monitoring.get("diagnostic_settings"):
        return []
    return [{
        "rule_id": "AZ-ACT-002",
        "severity": "MEDIUM",
        "resource": "abonnement Azure",
        "message": "Aucun diagnostic setting d'abonnement actif : la télémétrie "
                   "et les alertes de sécurité ne sont pas centralisées.",
    }]


def run_all_azure_rules(azure_data):
    """Point d'entrée principal : traite le dict du scanner."""
    findings = []
    findings += check_storage_public(azure_data["storage"])
    findings += check_storage_https(azure_data["storage"])
    findings += check_storage_shared_key(azure_data["storage"])
    findings += check_nsg_open_internet(azure_data["nsg"])
    findings += check_nsg_ssh_rdp(azure_data["nsg"])
    findings += check_activity_log(azure_data["monitoring"])
    findings += check_diagnostic_settings(azure_data["monitoring"])
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from azure_reader.azure_scanner import scan_azure

    data = scan_azure()
    findings = run_all_azure_rules(data)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")