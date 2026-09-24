"""
azure_reader/azure_scanner.py

Lit des ressources Azure et les renvoie normalisées (même philosophie que
aws_reader). Aucune décision de sécurité ici -> c'est le job de rules_engine.

IMPORTANT : le SDK Azure n'est PAS installé par défaut et l'utilisateur n'a
pas forcément de credentials. On garde donc les imports du SDK **à l'intérieur**
des fonctions et on capture proprement les erreurs : si le SDK manque ou
l'authentification échoue, le scanner renvoie des données vides + un message
clair, au lieu de faire crasher tout le pipeline (robustesse).
"""

import os


def _have_azure_sdk():
    try:
        import azure.identity  # noqa: F401
        import azure.mgmt.storage  # noqa: F401
        import azure.mgmt.network  # noqa: F401
        import azure.mgmt.monitor  # noqa: F401
        return True
    except ImportError:
        return False


def _get_subscription_id():
    return os.getenv("AZURE_SUBSCRIPTION_ID")


def scan_azure():
    """
    Point d'entrée principal du lecteur Azure.
    Renvoie un dict {"storage": [...], "nsg": [...], "monitoring": {...}}.

    Si le SDK est absent ou l'auth échoue -> dict vide + message, pas d'exception.
    """
    if not _have_azure_sdk():
        print("   [Azure] SDK non installé -> Azure ignoré (pip install -r requirements.txt).")
        return None

    sub_id = _get_subscription_id()
    if not sub_id:
        print("   [Azure] AZURE_SUBSCRIPTION_ID manquant -> Azure ignoré.")
        return None

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except Exception as e:  # noqa: BLE001
        print(f"   [Azure] authentification impossible ({type(e).__name__}) -> ignoré.")
        return _empty_data()

    data = _empty_data()
    data["storage"] = _list_storage_accounts(credential, sub_id)
    data["nsg"] = _list_network_security_groups(credential, sub_id)
    data["monitoring"] = _get_monitoring(credential, sub_id)
    return data


def _empty_data():
    return {"storage": [], "nsg": [], "monitoring": {"activity_log_configured": False,
                                                     "diagnostic_settings": False}}


def _list_storage_accounts(credential, sub_id):
    """
    Pour chaque storage account :
    - public_access : accès blob public autorisé ?
    - https_only : trafic HTTPS forcé ?
    - encrypted : chiffrement au repos activé ?
    - key_auth_enabled : clé partagée (shared key) autorisée ?
    """
    from azure.mgmt.storage import StorageManagementClient

    client = StorageManagementClient(credential, sub_id)
    result = []
    for acct in client.storage_accounts.list():
        props = acct
        result.append({
            "name": acct.name,
            "resource_group": acct.id.split("/")[4],
            "public_access": getattr(props, "allow_blob_public_access", False) or \
                             (getattr(props, "public_network_access", "Enabled") == "Enabled"
                              and getattr(props, "allow_blob_public_access", False)),
            "https_only": bool(getattr(props, "supports_https_traffic_only", False)),
            "encrypted": bool(getattr(getattr(props, "encryption", None), "services", None)),
            "key_auth_enabled": bool(getattr(props, "allow_shared_key_access", True)),
        })
    return result


def _list_network_security_groups(credential, sub_id):
    """
    Pour chaque NSG :
    - open_to_internet : règle entrante autorisant Internet (service tag 'Internet' ou 0.0.0.0/0)
    - ssh_rdp_open_to_internet : port 22 ou 3389 ouvert depuis Internet
    """
    from azure.mgmt.network import NetworkManagementClient

    client = NetworkManagementClient(credential, sub_id)
    result = []
    for nsg in client.network_security_groups.list_all():
        open_internet = False
        ssh_rdp = False
        for rule in getattr(nsg, "security_rules", []) or []:
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            src = rule.source_address_prefix
            is_internet = src in ("Internet", "*", "0.0.0.0/0", "::/0")
            if not is_internet:
                continue
            open_internet = True
            ports = (rule.destination_port_range or "")
            if ports in ("22", "3389", "*") or "-" in ports and (22 <= _port_min(ports) <= 3389):
                ssh_rdp = True
        result.append({
            "name": nsg.name,
            "resource_group": nsg.id.split("/")[4],
            "open_to_internet": open_internet,
            "ssh_rdp_open_to_internet": ssh_rdp,
        })
    return result


def _port_min(port_range):
    try:
        return int(port_range.split("-")[0])
    except Exception:  # noqa: BLE001
        return 0


def _get_monitoring(credential, sub_id):
    """
    Vérifie la présence d'un log profile (activity log) et de diagnostic settings
    au niveau de l'abonnement (l'équivalent Azure de CloudTrail).
    """
    from azure.mgmt.monitor import MonitorManagementClient

    client = MonitorManagementClient(credential, sub_id)
    has_profile = any(True for _ in client.log_profiles.list())
    diag = any(True for _ in client.diagnostic_settings.list_by_subscription())
    return {"activity_log_configured": has_profile, "diagnostic_settings": diag}


if __name__ == "__main__":
    import json

    data = scan_azure()
    if data is None:
        print("Azure non configuré (SDK absent ou pas de credentials).")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))