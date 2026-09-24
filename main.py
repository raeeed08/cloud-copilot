"""
main.py

Point d'entrée principal du copilot. Orchestre le pipeline complet :
1. Lecture des ressources cloud (aws_reader)
2. Application des règles de sécurité (rules_engine)
3. Génération de conseils en langage naturel (llm.advisor)

Le pipeline est PILOTÉ PAR DONNÉES : une liste de paires (scanner, règles).
Ajouter un service = ajouter une ligne dans SERVICES, rien d'autre.
"""

import json

from aws_reader.iam_scanner import list_users
from aws_reader.s3_scanner import list_buckets
from aws_reader.ec2_scanner import list_security_groups
from aws_reader.cloudtrail_scanner import list_trails
from aws_reader.rds_scanner import list_db_instances, list_db_snapshots
from azure_reader.azure_scanner import scan_azure
from rules_engine.iam_rules import run_all_iam_rules
from rules_engine.s3_rules import run_all_s3_rules
from rules_engine.ec2_rules import run_all_ec2_rules
from rules_engine.cloudtrail_rules import run_all_cloudtrail_rules
from rules_engine.rds_rules import run_all_rds_rules
from rules_engine.azure_rules import run_all_azure_rules
from llm.advisor import explain_findings

# Chaque triplet (scanner, règles, provider) suit le même contrat :
# scanner() -> données normalisées, règles(données) -> findings.
# Le provider est taggé sur chaque finding pour le filtre AWS/Azure du dashboard.
SERVICES = [
    (list_users, run_all_iam_rules, "AWS"),
    (list_buckets, run_all_s3_rules, "AWS"),
    (list_security_groups, run_all_ec2_rules, "AWS"),
    (list_trails, run_all_cloudtrail_rules, "AWS"),
    (lambda: {"instances": list_db_instances(), "snapshots": list_db_snapshots()},
     run_all_rds_rules, "AWS"),
    (scan_azure, run_all_azure_rules, "Azure"),
]


def run_full_scan():
    """Lance tous les services, combine les findings, génère l'analyse LLM."""
    all_findings = []

    for scanner, rules, provider in SERVICES:
        print(f" Scan {scanner.__name__} ({provider})...")
        data = scanner()
        if data is None:
            # Service non configuré (ex: Azure sans SDK/credentials) -> on ignore.
            print("   -> ignoré (service non configuré)")
            continue
        findings = rules(data)
        for f in findings:
            f.setdefault("provider", provider)
        all_findings += findings
        print(f"   -> {len(findings)} finding(s)")

    print(" Génération de l'analyse...\n")
    explanation = explain_findings(all_findings)

    return {
        "findings": all_findings,
        "explanation": explanation,
    }


if __name__ == "__main__":
    report = run_full_scan()

    print("=" * 60)
    print("RAPPORT DE SCAN")
    print("=" * 60)
    print(report["explanation"])

    with open("data/last_scan.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n Rapport complet sauvegardé dans data/last_scan.json")