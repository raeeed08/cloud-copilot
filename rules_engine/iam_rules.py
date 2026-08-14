"""
rules_engine/iam_rules.py

Ce module prend les données IAM déjà lues (par aws_reader/iam_scanner.py)
et applique des règles de sécurité dessus. Il ne parle JAMAIS directement
à AWS -> il ne travaille que sur les données Python qu'on lui donne.

C'est ce découplage qui te permettra plus tard de brancher Azure sur le
MÊME moteur de règles, tant que les données Azure sont normalisées dans
un format similaire.

Chaque règle retourne un "finding" (constat) sous forme de dict avec :
- rule_id     : identifiant unique de la règle
- severity    : "HIGH", "MEDIUM", "LOW"
- resource    : quelle ressource est concernée
- message     : description humaine du problème
"""


def check_mfa_disabled(users):
    """Règle IAM-002 : utilisateur actif sans MFA activé."""
    findings = []
    for user in users:
        if not user["mfa_enabled"]:
            findings.append({
                "rule_id": "IAM-002",
                "severity": "HIGH",
                "resource": user["username"],
                "message": f"L'utilisateur '{user['username']}' n'a pas MFA activé. "
                           f"Un compte sans MFA est vulnérable si le mot de passe ou "
                           f"la clé est compromis.",
            })
    return findings


def check_direct_admin_policy(users):
    """Règle IAM-001 : policy admin/wildcard attachée directement à un user."""
    ADMIN_POLICIES = {"AdministratorAccess"}
    findings = []
    for user in users:
        for policy in user["attached_policies"]:
            if policy in ADMIN_POLICIES:
                findings.append({
                    "rule_id": "IAM-001",
                    "severity": "HIGH",
                    "resource": user["username"],
                    "message": f"L'utilisateur '{user['username']}' a la politique "
                               f"'{policy}' attachée DIRECTEMENT (au lieu de passer par "
                               f"un groupe IAM). Ça rend la gestion des permissions plus "
                               f"difficile à auditer et à révoquer.",
                })
    return findings


def check_stale_access_keys(users, max_age_days=90):
    """Règle IAM-003 : access key non tournée depuis plus de max_age_days jours."""
    findings = []
    for user in users:
        for key in user["access_keys"]:
            if key["status"] == "Active" and key["age_days"] > max_age_days:
                findings.append({
                    "rule_id": "IAM-003",
                    "severity": "MEDIUM",
                    "resource": user["username"],
                    "message": f"La clé d'accès de '{user['username']}' a "
                               f"{key['age_days']} jours (créée le {key['created_date']}). "
                               f"Les clés statiques anciennes augmentent le risque en cas "
                               f"de fuite non détectée.",
                })
    return findings


def check_direct_policy_instead_of_group(users):
    """
    Règle IAM-005 : toute politique managée attachée directement à un user
    (au-delà du cas admin déjà couvert par IAM-001) est une mauvaise pratique.
    """
    findings = []
    for user in users:
        non_admin_policies = [p for p in user["attached_policies"] if p != "AdministratorAccess"]
        for policy in non_admin_policies:
            findings.append({
                "rule_id": "IAM-005",
                "severity": "LOW",
                "resource": user["username"],
                "message": f"La politique '{policy}' est attachée directement à "
                           f"'{user['username']}' plutôt qu'à un groupe IAM.",
            })
    return findings


def run_all_iam_rules(users):
    """
    Point d'entrée principal : lance toutes les règles IAM et renvoie
    la liste combinée de tous les findings.
    """
    findings = []
    findings += check_mfa_disabled(users)
    findings += check_direct_admin_policy(users)
    findings += check_stale_access_keys(users)
    findings += check_direct_policy_instead_of_group(users)
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    # Permet d'importer aws_reader même en lançant ce fichier directement
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.iam_scanner import list_users

    users = list_users()
    findings = run_all_iam_rules(users)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")
