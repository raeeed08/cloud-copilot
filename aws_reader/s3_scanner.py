"""
aws_reader/s3_scanner.py

Même logique que iam_scanner.py : ce module lit l'état des buckets S3
et renvoie des données normalisées. Aucune décision de sécurité ici.
"""

import boto3
from botocore.exceptions import ClientError


def get_s3_client(region="eu-west-1"):
    return boto3.client("s3", region_name=region)


def list_buckets(client=None):
    """
    Récupère tous les buckets S3 du compte, avec pour chacun :
    - son nom, date de création
    - s'il est public ou non
    - si le chiffrement au repos est activé
    - si le versioning est activé
    - si les access logs sont activés
    """
    if client is None:
        client = get_s3_client()

    buckets_data = []

    response = client.list_buckets()
    for bucket in response["Buckets"]:
        name = bucket["Name"]

        bucket_info = {
            "name": name,
            "created_date": bucket["CreationDate"].isoformat(),
            "is_public": _is_public(client, name),
            "encryption_enabled": _has_encryption(client, name),
            "versioning_enabled": _has_versioning(client, name),
            "logging_enabled": _has_logging(client, name),
        }
        buckets_data.append(bucket_info)

    return buckets_data


def _is_public(client, bucket_name):
    """
    Vérifie si le bucket est accessible publiquement.
    On regarde le "Public Access Block" -> si AWS bloque bien tout accès
    public, alors le bucket est protégé. Si la config n'existe pas du tout
    ou si un des blocages est désactivé, on considère le bucket à risque.
    """
    try:
        response = client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        # Le bucket est "protégé" seulement si LES 4 blocages sont activés
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        return not all_blocked
    except ClientError as e:
        # Si aucune config de blocage n'existe -> AWS renvoie une erreur
        # "NoSuchPublicAccessBlockConfiguration" -> ça veut dire rien n'est
        # bloqué -> on considère ça comme potentiellement public (à risque)
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return True
        raise  # une autre erreur inattendue -> on la laisse remonter


def _has_encryption(client, bucket_name):
    """Vérifie si le chiffrement par défaut est activé sur le bucket."""
    try:
        client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        raise


def _has_versioning(client, bucket_name):
    """Vérifie si le versioning est activé."""
    response = client.get_bucket_versioning(Bucket=bucket_name)
    # Si jamais activé, la clé "Status" n'existe même pas dans la réponse
    return response.get("Status") == "Enabled"


def _has_logging(client, bucket_name):
    """Vérifie si les access logs sont activés sur le bucket."""
    response = client.get_bucket_logging(Bucket=bucket_name)
    # Si les logs ne sont pas configurés, "LoggingEnabled" n'existe pas
    return "LoggingEnabled" in response


if __name__ == "__main__":
    import json

    buckets = list_buckets()
    print(json.dumps(buckets, indent=2, ensure_ascii=False))
