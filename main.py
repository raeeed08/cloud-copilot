"""
main.py

Point d'entrée principal du copilot. Orchestre le pipeline complet :
1. Lecture des ressources cloud (aws_reader)
2. Application des règles de sécurité (rules_engine)
3. Génération de conseils en langage naturel (llm.advisor)
"""

import json

from aws_reader.iam_scanner import list_users
from aws_reader.s3_scanner import list_buckets
from rules_engine.iam_rules import run_all_iam_rules
from rules_engine.s3_rules import run_all_s3_rules
from llm.advisor import explain_findings


def run_full_scan():
    print(" Lecture des ressources IAM sur AWS...")
    users = list_users()
    print(f"   -> {len(users)} utilisateur(s) trouvé(s)")

    print(" Lecture des buckets S3 sur AWS...")
    buckets = list_buckets()
    print(f"   -> {len(buckets)} bucket(s) trouvé(s)")

    print(" Application des règles de sécurité...")
    findings = run_all_iam_rules(users) + run_all_s3_rules(buckets)
    print(f"   -> {len(findings)} finding(s) détecté(s)")

    print(" Génération de l'analyse...\n")
    explanation = explain_findings(findings)

    return {
        "findings": findings,
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
