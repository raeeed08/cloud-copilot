"""
web app : expose le pipeline cloud-copilot sous forme de dashboard web.

Sert index.html (design Stitch) + une petite API JSON que le front consomme :
- GET  /api/scan     -> derniers findings transformés + score + explication
- POST /api/run-scan -> relance le pipeline réel (AWS) et retourne les données
- POST /api/chat     -> pose une question au LLM (contexte = findings)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, request

from main import run_full_scan

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "data", "last_scan.json")

app = Flask(__name__, template_folder="templates")

# Sévérité du moteur (HIGH/MEDIUM/LOW) -> sévérité du design (CRITICAL/HIGH/LOW)
SEVERITY_MAP = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "LOW"}
SEVERITY_WEIGHT = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2}

# Snippets Terraform de remédiation, générés depuis le rule_id.
REMEDIATION = {
    "IAM-001": 'resource "aws_iam_group" "admins" {\n  name = "Admins"\n}\n\nresource "aws_iam_group_policy_attachment" "admin" {\n  group = aws_iam_group.admins.name\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}',
    "IAM-002": 'resource "aws_iam_user_mfa" "this" {\n  # Activez MFA pour l\'utilisateur via la console IAM\n  # (la MFA ne peut pas être créée par Terraform)\n  user_name = "<RESOURCE>"\n}',
    "IAM-003": '# Faites tourner la clé d\'accès via la console IAM :\n# aws iam create-access-key --user-name <RESOURCE>',
    "IAM-005": 'resource "aws_iam_group_policy_attachment" "this" {\n  group      = "<GROUPE>"\n  policy_arn = "arn:aws:iam::aws:policy/<POLICY>"\n}',
    "S3-001": 'resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = "<RESOURCE>"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
    "S3-002": 'resource "aws_s3_bucket_server_side_encryption_configuration" "this" {\n  bucket = "<RESOURCE>"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}',
    "S3-003": 'resource "aws_s3_bucket_versioning" "this" {\n  bucket = "<RESOURCE>"\n  versioning_configuration {\n    status = "Enabled"\n  }\n}',
    "S3-004": 'resource "aws_s3_bucket_logging" "this" {\n  bucket        = "<RESOURCE>"\n  target_bucket = "<LOG_BUCKET>"\n  target_prefix = "logs/"\n}',
    "EC2-001": 'resource "aws_security_group" "this" {\n  # Restreignez les plages CIDR aux IP de confiance, ne pas utiliser 0.0.0.0/0\n  name   = "<RESOURCE>"\n  vpc_id = "<VPC_ID>"\n}',
    "EC2-002": '# SSH/RDP ne doivent pas être ouverts au monde :\n# autorisez uniquement vos IP de confiance (ex: 203.0.113.0/24)',
    "CT-001": 'resource "aws_cloudtrail" "this" {\n  name                          = "account-trail"\n  s3_bucket_name                = "<LOG_BUCKET>"\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n}',
    "CT-002": 'resource "aws_cloudtrail" "this" {\n  name               = "account-trail"\n  is_multi_region_trail = true\n}',
    "CT-003": 'resource "aws_cloudtrail" "this" {\n  name                    = "account-trail"\n  enable_log_file_validation = true\n}',
    "CT-004": '# Activez la journalisation : aws cloudtrail start-logging --name <RESOURCE>',
    "RDS-001": 'resource "aws_db_instance" "this" {\n  # publicly_accessible = false (défaut)\n  identifier     = "<RESOURCE>"\n  # placez l\'instance dans un subnet privé\n}',
    "RDS-002": 'resource "aws_db_instance" "this" {\n  identifier            = "<RESOURCE>"\n  storage_encrypted     = true\n  kms_key_id            = "<KMS_ARN>"\n}',
    "RDS-003": '# Révoquez le partage public :\n# aws rds modify-db-snapshot-attribute --db-snapshot-identifier <RESOURCE> \\\n#   --attribute-name restore --values-to-remove all',
}


def transform_findings(raw_findings):
    """Normalise les findings du moteur vers le schéma attendu par le front."""
    out = []
    for f in raw_findings:
        sev = SEVERITY_MAP.get(f.get("severity"), f.get("severity"))
        rule_prefix = f.get("rule_id", "").split("-")[0]
        snippet = REMEDIATION.get(f.get("rule_id")) or REMEDIATION.get(rule_prefix, "")
        out.append({
            "rule_id": f.get("rule_id"),
            "severity": sev,
            "provider": f.get("provider", "AWS"),
            "resource_name": f.get("resource"),
            "message": f.get("message"),
            "remediation": {"terraform": snippet.replace("<RESOURCE>", str(f.get("resource", "")))},
        })
    return out


def compute_security_score(findings):
    """Score 0-100 décroissant avec la sévérité/cumul des findings."""
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 2) for f in findings)
    return max(0, 100 - penalty)


def load_report():
    if not os.path.exists(DATA_FILE):
        return None
    with open(DATA_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan")
def api_scan():
    report = load_report()
    if not report:
        return jsonify({"findings": [], "security_score": 100, "explanation": "",
                        "last_scan": None})
    findings = transform_findings(report.get("findings", []))
    return jsonify({
        "findings": findings,
        "security_score": compute_security_score(findings),
        "explanation": report.get("explanation", ""),
        "last_scan": os.path.getmtime(DATA_FILE),
    })


@app.route("/api/run-scan", methods=["POST"])
def api_run_scan():
    report = run_full_scan()
    findings = transform_findings(report.get("findings", []))
    return jsonify({
        "findings": findings,
        "security_score": compute_security_score(findings),
        "explanation": report.get("explanation", ""),
        "last_scan": os.path.getmtime(DATA_FILE),
    })


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(force=True, silent=True) or {}
    question = data.get("message", "")
    report = load_report()
    findings = report.get("findings", []) if report else []

    from llm.advisor import client, MODELS

    context = json.dumps(findings, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content":
         "Tu es le Copilot de sécurité cloud. Réponds en français, concis, "
         "avec des étapes concrètes. Ne propose jamais d'action destructive "
         "sans avertir."},
        {"role": "user", "content":
         f"Contexte (findings détectés sur le compte AWS) :\n{context}\n\n"
         f"Question de l'utilisateur : {question}"},
    ]

    last_error = None
    for model in MODELS:
        try:
            resp = client.chat.completions.create(model=model, max_tokens=800,
                                                  messages=messages)
            return jsonify({"reply": resp.choices[0].message.content})
        except Exception as e:  # noqa: BLE001
            last_error = e
    return jsonify({"reply": f"[LLM indisponible : {type(last_error).__name__}] "
                            f"Vérifiez votre clé OpenRouter."}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
