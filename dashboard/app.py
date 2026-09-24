"""
dashboard/app.py

Mini serveur web qui affiche le contenu de data/last_scan.json
(le dernier rapport généré par main.py) dans une page HTML lisible.

Ce fichier ne relance JAMAIS de scan lui-même -> il lit uniquement
le fichier JSON déjà produit. Séparation claire : main.py = scan,
dashboard = affichage.
"""

import json
import os
from flask import Flask, render_template

app = Flask(__name__)

DATA_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "last_scan.json",
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@app.route("/")
def dashboard():
    if not os.path.exists(DATA_FILE):
        return "Aucun scan trouvé. Lance d'abord `python main.py` à la racine du projet."

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    findings_sorted = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 3)
    )

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1

    return render_template(
        "index.html",
        findings=findings_sorted,
        explanation=report.get("explanation", ""),
        counts=counts,
        total=len(findings),
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
