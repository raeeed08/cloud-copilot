# 14: Cheat sheet

## Project
```bash
make install | dev | test | lint | security | check | docs | scan | mcp | up | down | kind | tf-check | helm-check
uv run cloud-copilot scan [--provider aws] [--fail-on CRITICAL] [--output json]
uv run cloud-copilot rules [--provider azure] | ask "what first?" | mcp [--transport http] | db-upgrade
```

## API (http://localhost:8000/api/docs)
```bash
curl localhost:8000/api/v1/info
curl -X POST localhost:8000/api/v1/scans -H 'content-type: application/json' -d '{"demo":true}'
curl -X POST localhost:8000/api/v1/scans -H 'content-type: application/json' -d '{"account_ids":["<id>"]}'
curl localhost:8000/api/v1/plan | jq '.phases[] | {horizon, actions: (.actions|length), score_gain}'
curl localhost:8000/api/v1/scans/<id>/diff
curl "localhost:8000/api/v1/findings?severity=CRITICAL&provider=aws"
curl -X PUT localhost:8000/api/v1/settings/llm -H 'content-type: application/json' -d '{"provider":"groq","api_key":"gsk_…"}'
curl -X POST localhost:8000/api/v1/settings/llm/test
curl "localhost:8000/api/v1/findings/export?fmt=md" -o report.md
```

## Docker / Compose (via the CLI image if plugins are missing)
```bash
alias dcli='docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:$PWD -w $PWD -e HOME=$HOME docker:27.4-cli'
dcli docker buildx build --load -t cloud-copilot:local .
dcli docker compose up -d --build | ps | logs -f api | down [-v]
docker exec -it cloud-copilot-postgres-1 psql -U copilot
```

## Kubernetes / Helm
```bash
kubectl get pods,svc,deploy,hpa,cronjob -n cc -o wide
kubectl describe pod <p> -n cc ; kubectl logs <p> -n cc --previous
kubectl port-forward svc/cc-cloud-copilot 8000:80 -n cc
kubectl rollout status|history|undo deploy/cc-cloud-copilot -n cc
kubectl create job --from=cronjob/cc-cloud-copilot-scan now -n cc
helm upgrade --install cc deploy/helm/cloud-copilot -n cc --create-namespace -f deploy/helm/cloud-copilot/values-demo.yaml
helm list -A ; helm history cc -n cc ; helm rollback cc 1 -n cc ; helm test cc -n cc
docker run --rm -v $PWD:/w -w /w alpine/helm:3.16.4 lint deploy/helm/cloud-copilot --strict
```

## Argo CD
```bash
argocd app list ; argocd app diff <app> ; argocd app sync <app> ; argocd app rollback <app> <id>
```

## Terraform
```bash
terraform fmt -recursive ; terraform init [-backend-config=backend.hcl] ; terraform validate
terraform plan -out p ; terraform apply p ; terraform output [-raw x] ; terraform destroy
terraform state list ; terraform state show <addr> ; terraform import <addr> <id>
```

## AWS CLI
```bash
aws sts get-caller-identity
aws configure list ; aws configure --profile lab
aws sts assume-role --role-arn <arn> --role-session-name me --external-id <id>
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
aws s3api get-public-access-block --bucket <b>
aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress
aws ec2 modify-instance-metadata-options --instance-id <i> --http-tokens required
aws ec2 modify-volume --volume-id <v> --volume-type gp3
aws ce get-cost-and-usage --time-period Start=2026-10-01,End=2026-11-01 --granularity MONTHLY --metrics UnblendedCost
```

## Azure CLI
```bash
az login ; az account show ; az account set -s <sub>
az ad sp create-for-rbac --name cloud-copilot --role Reader --scopes /subscriptions/<sub>
az role assignment create --assignee <appId> --role "Security Reader" --scope /subscriptions/<sub>
az network nsg rule list -g <rg> --nsg-name <nsg> -o table
az storage account update -n <st> -g <rg> --allow-blob-public-access false --min-tls-version TLS1_2
az keyvault update -n <kv> --enable-purge-protection true
```

## GitHub
```bash
gh repo create ; gh pr create --fill ; gh pr checks ; gh run watch ; gh run view --log-failed
cosign verify ghcr.io/<owner>/cloud-copilot@<digest> --certificate-identity-regexp '…' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Observability (PromQL)
```promql
copilot_posture_score
sum by (severity) (copilot_findings)
histogram_quantile(0.95, sum by (le, route) (rate(copilot_http_request_seconds_bucket[5m])))
sum(rate(copilot_llm_requests_total{outcome="error"}[15m])) / sum(rate(copilot_llm_requests_total[15m]))
```

## Rule ID prefixes
`IAM` identity · `S3` · `EC2`/`EBS`/`VPC` · `CT` CloudTrail · `GD`/`CFG`/`SH` detection · `RDS` · `DDB` · `KMS` ·
`SM` secrets · `MSG` SQS/SNS · `LAMBDA` · `ELB` · `EKS` · `ECR` · `ACM` · `LOGS` · `COST` ·
`AZ-STOR` · `AZ-NSG` · `AZ-KV` · `AZ-SQL` · `AZ-VM`/`AZ-DISK` · `AZ-APP` · `AZ-MON` · `AZ-DEF` · `AZ-AKS` · `AZ-ACR` ·
`AZ-COST`. Full list: `docs/rules.md`.
