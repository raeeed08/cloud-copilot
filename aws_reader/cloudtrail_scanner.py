"""
aws_reader/cloudtrail_scanner.py

Lit les trails CloudTrail d'un compte AWS et renvoie des données normalisées.
Aucune décision de sécurité ici -> c'est le job de rules_engine.
"""

import boto3


def get_cloudtrail_client(region="eu-west-1"):
    return boto3.client("cloudtrail", region_name=region)


def list_trails(client=None):
    """
    Pour chaque trail CloudTrail :
    - nom
    - multi_region : couvre toutes les régions ?
    - log_validation : les logs sont signés (détection de falsification) ?
    - is_logging : le trail est-il actif ?
    """
    if client is None:
        client = get_cloudtrail_client()

    response = client.describe_trails()
    # La clé de la réponse peut être "TrailList" (doc AWS) ou "trailList"
    # (selon la version de botocore) -> on accepte les deux.
    trails = response.get("TrailList") or response.get("trailList") or []
    trails_data = []

    for trail in trails:
        status = client.get_trail_status(Name=trail["Name"])
        trails_data.append({
            "name": trail["Name"],
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "log_validation": trail.get("LogFileValidationEnabled", False),
            "is_logging": status.get("IsLogging", False),
        })

    return trails_data


if __name__ == "__main__":
    import json

    trails = list_trails()
    print(json.dumps(trails, indent=2, ensure_ascii=False))
