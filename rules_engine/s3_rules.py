"""
rules_engine/s3_rules.py

Règles de sécurité appliquées aux données S3 lues par aws_reader/s3_scanner.py.
Même principe que iam_rules.py : fonctions pures, aucun appel direct à AWS.
"""


def check_public_bucket(buckets):
    """Règle S3-001 : bucket accessible publiquement."""
    findings = []
    for bucket in buckets:
        if bucket["is_public"]:
            findings.append({
                "rule_id": "S3-001",
                "severity": "HIGH",
                "resource": bucket["name"],
                "message": f"Le bucket '{bucket['name']}' n'a pas de blocage "
                           f"d'accès public complet activé. Il peut être exposé "
                           f"à une lecture ou écriture publique non désirée.",
            })
    return findings


def check_encryption_disabled(buckets):
    """Règle S3-002 : chiffrement au repos désactivé."""
    findings = []
    for bucket in buckets:
        if not bucket["encryption_enabled"]:
            findings.append({
                "rule_id": "S3-002",
                "severity": "MEDIUM",
                "resource": bucket["name"],
                "message": f"Le bucket '{bucket['name']}' n'a pas de chiffrement "
                           f"par défaut activé. Les données stockées ne sont pas "
                           f"protégées au repos.",
            })
    return findings


def check_versioning_disabled(buckets):
    """Règle S3-003 : versioning désactivé."""
    findings = []
    for bucket in buckets:
        if not bucket["versioning_enabled"]:
            findings.append({
                "rule_id": "S3-003",
                "severity": "LOW",
                "resource": bucket["name"],
                "message": f"Le bucket '{bucket['name']}' n'a pas le versioning "
                           f"activé. En cas de suppression ou modification "
                           f"accidentelle, les données ne pourront pas être "
                           f"restaurées.",
            })
    return findings


def check_logging_disabled(buckets):
    """Règle S3-004 : access logs désactivés."""
    findings = []
    for bucket in buckets:
        if not bucket["logging_enabled"]:
            findings.append({
                "rule_id": "S3-004",
                "severity": "LOW",
                "resource": bucket["name"],
                "message": f"Le bucket '{bucket['name']}' n'a pas les access "
                           f"logs activés. En cas d'incident, il sera difficile "
                           f"de savoir qui a accédé aux données et quand.",
            })
    return findings


def run_all_s3_rules(buckets):
    """Point d'entrée principal : lance toutes les règles S3."""
    findings = []
    findings += check_public_bucket(buckets)
    findings += check_encryption_disabled(buckets)
    findings += check_versioning_disabled(buckets)
    findings += check_logging_disabled(buckets)
    return findings


if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.s3_scanner import list_buckets

    buckets = list_buckets()
    findings = run_all_s3_rules(buckets)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"\n{len(findings)} findings détectés.")
