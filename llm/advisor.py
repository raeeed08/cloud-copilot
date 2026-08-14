"""
llm/advisor.py

Ce module prend une liste de findings (produits par rules_engine) et
demande au modèle (via OpenRouter, un gateway compatible OpenAI) de
générer une explication claire + des recommandations concrètes.

Il ne modifie JAMAIS l'infrastructure -> lecture seule des findings,
génération de texte uniquement.
"""

import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")
if not API_KEY:
    raise SystemExit("Erreur : OPENROUTER_API_KEY manquante dans .env")

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
)

MODELS = [
    "openrouter/free",                # auto-router : choisit un modèle gratuit dispo
    "openai/gpt-oss-20b:free",
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
]


def explain_findings(findings):
    """
    Prend une liste de findings (dicts) et renvoie un texte d'explication
    généré par le modèle, avec priorisation et recommandations concrètes.
    """
    if not findings:
        return "Aucun problème détecté par les règles actuelles."

    findings_json = json.dumps(findings, indent=2, ensure_ascii=False)

    system_prompt = (
        "Tu es un assistant expert en sécurité cloud (AWS/Azure). "
        "On te donne une liste de findings détectés automatiquement par un "
        "moteur de règles. Ton rôle : "
        "1) Prioriser les findings par ordre d'urgence réelle "
        "2) Expliquer simplement pourquoi chacun est un risque "
        "3) Donner une recommandation d'action concrète et courte "
        "Réponds en français, de façon structurée et concise. "
        "Ne recommande jamais d'action destructive sans avertissement."
    )

    for model in MODELS:
        try:
            response = client.chat.completions.create(
                model=model,
                max_tokens=1500,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Voici les findings détectés :\n\n{findings_json}"},
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"\n[AVERTISSEMENT] Modèle '{model}' indisponible ({type(e).__name__}) : "
                  f"essai du modèle suivant.\n")

    print(f"\n[AVERTISSEMENT] Analyse LLM indisponible : "
          f"génération d'un rapport de secours sans IA.\n")
    return _fallback_summary(findings)


def _fallback_summary(findings):
    """Rapport de secours sans LLM : trie les findings par sévérité."""
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity"), 3),
    )

    lines = ["RAPPORT DE SCAN (généré sans IA - mode secours)", ""]
    for f in sorted_findings:
        lines.append(f"[{f.get('severity')}] {f.get('rule_id')} - {f.get('resource')}")
        lines.append(f"    {f.get('message')}")
    lines.append("")
    lines.append("Astuce : vérifiez votre clé OpenRouter (sk-or-...) ou vos quotas")
    lines.append("gratuits (50 req/jour sans crédit) pour obtenir des recommandations IA.")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aws_reader.iam_scanner import list_users
    from rules_engine.iam_rules import run_all_iam_rules

    users = list_users()
    findings = run_all_iam_rules(users)

    print("--- Findings bruts ---")
    print(json.dumps(findings, indent=2, ensure_ascii=False))

    print("\n--- Analyse ---\n")
    explanation = explain_findings(findings)
    print(explanation)
