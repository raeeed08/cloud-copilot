"""
aws_reader/ec2_scanner.py

Lit les security groups EC2 d'un compte AWS et renvoie des données normalisées.
Aucune décision de sécurité ici -> c'est le job de rules_engine.
"""

import boto3


def get_ec2_client(region="eu-west-1"):
    return boto3.client("ec2", region_name=region)


def _is_open_to_world(ip_permissions):
    """
    Vrai si au moins une permission autorise le trafic depuis 0.0.0.0/0 ou ::/0.
    """
    for permission in ip_permissions:
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                return True
        for ipv6_range in permission.get("Ipv6Ranges", []):
            if ipv6_range.get("CidrIpv6") == "::/0":
                return True
    return False


def _has_ssh_rdp(ip_permissions):
    """
    Vrai si une permission ouvre le port SSH (22) ou RDP (3389).
    """
    for permission in ip_permissions:
        port = permission.get("FromPort")
        if port in (22, 3389):
            return True
    return False


def list_security_groups(client=None):
    """
    Pour chaque security group :
    - id, nom
    - open_to_world : ouvert au monde entier (0.0.0.0/0)
    - ssh_rdp_open_to_world : SSH/RDP ouvert au monde entier
    """
    if client is None:
        client = get_ec2_client()

    response = client.describe_security_groups()
    sgs_data = []

    for sg in response["SecurityGroups"]:
        ip_permissions = sg.get("IpPermissions", [])
        open_to_world = _is_open_to_world(ip_permissions)
        ssh_rdp = open_to_world and _has_ssh_rdp(ip_permissions)

        sgs_data.append({
            "id": sg["GroupId"],
            "name": sg["GroupName"],
            "open_to_world": open_to_world,
            "ssh_rdp_open_to_world": ssh_rdp,
        })

    return sgs_data


if __name__ == "__main__":
    import json

    sgs = list_security_groups()
    print(json.dumps(sgs, indent=2, ensure_ascii=False))
