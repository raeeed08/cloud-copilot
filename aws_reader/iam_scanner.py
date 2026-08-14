"""
aws_reader/iam_scanner.py

Ce module lit les ressources IAM (Identity and Access Management) d'un compte AWS
et les renvoie sous forme de données Python simples (list of dicts).

Il ne prend AUCUNE décision de sécurité ici -> ça, c'est le job du rules_engine.
Ce fichier fait UNE seule chose : lire et normaliser les données brutes d'AWS.
"""

import boto3
from datetime import datetime, timezone


def get_iam_client(region="eu-west-1"):
    return boto3.client("iam", region_name=region)


def list_users(client=None):
    if client is None:
        client = get_iam_client()

    users_data = []

    paginator = client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            user_info = {
                "username": username,
                "arn": user["Arn"],
                "created_date": user["CreateDate"].isoformat(),
                "mfa_enabled": _has_mfa(client, username),
                "access_keys": _get_access_keys_info(client, username),
                "attached_policies": _get_attached_policies(client, username),
            }
            users_data.append(user_info)

    return users_data


def _has_mfa(client, username):
    response = client.list_mfa_devices(UserName=username)
    return len(response["MFADevices"]) > 0


def _get_access_keys_info(client, username):
    response = client.list_access_keys(UserName=username)
    keys_info = []

    for key in response["AccessKeyMetadata"]:
        created = key["CreateDate"]
        age_days = (datetime.now(timezone.utc) - created).days

        keys_info.append({
            "access_key_id": key["AccessKeyId"],
            "status": key["Status"],
            "created_date": created.isoformat(),
            "age_days": age_days,
        })

    return keys_info


def _get_attached_policies(client, username):
    response = client.list_attached_user_policies(UserName=username)
    return [p["PolicyName"] for p in response["AttachedPolicies"]]


if __name__ == "__main__":
    import json

    users = list_users()
    print(json.dumps(users, indent=2, ensure_ascii=False))
