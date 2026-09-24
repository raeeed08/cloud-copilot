"""
aws_reader/rds_scanner.py

Lit les instances et snapshots RDS d'un compte AWS et renvoie
des données normalisées. Aucune décision de sécurité ici.
"""

import boto3


def get_rds_client(region="eu-west-1"):
    return boto3.client("rds", region_name=region)


def list_db_instances(client=None):
    """
    Pour chaque instance RDS :
    - identifier
    - publicly_accessible : joignable depuis Internet ?
    - storage_encrypted : chiffrée au repos ?
    """
    if client is None:
        client = get_rds_client()

    instances_data = []
    response = client.describe_db_instances()

    for instance in response["DBInstances"]:
        instances_data.append({
            "identifier": instance["DBInstanceIdentifier"],
            "publicly_accessible": instance.get("PubliclyAccessible", False),
            "storage_encrypted": instance.get("StorageEncrypted", False),
        })

    return instances_data


def list_db_snapshots(client=None):
    """
    Pour chaque snapshot RDS :
    - identifier
    - is_public : partagé publiquement (n'importe qui peut le télécharger) ?
    """
    if client is None:
        client = get_rds_client()

    snapshots_data = []
    response = client.describe_db_snapshots()

    for snapshot in response["DBSnapshots"]:
        snap_id = snapshot["DBSnapshotIdentifier"]
        attributes = client.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snap_id
        )

        is_public = False
        for attribute in attributes["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
            if attribute["AttributeName"] == "restore" and "all" in attribute["AttributeValues"]:
                is_public = True

        snapshots_data.append({
            "identifier": snap_id,
            "is_public": is_public,
        })

    return snapshots_data


if __name__ == "__main__":
    import json

    instances = list_db_instances()
    snapshots = list_db_snapshots()

    print(json.dumps({"instances": instances, "snapshots": snapshots},
                     indent=2, ensure_ascii=False))