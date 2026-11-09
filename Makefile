.DEFAULT_GOAL := help
SHELL := /bin/bash
IMAGE ?= cloud-copilot:local

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

install: ## Install Python + web dependencies and git hooks
	uv sync --all-extras
	cd web && npm ci
	uv run pre-commit install || true

dev: ## Run API (reload) in demo mode on :8000
	DEMO_MODE=true SCAN_ON_STARTUP=true uv run cloud-copilot serve --reload

web-dev: ## Run the Vite dev server on :5173 (proxies /api to :8000)
	cd web && npm run dev

web-build: ## Build the dashboard into the Python package
	cd web && npm run build

lint: ## Ruff + mypy + eslint
	uv run ruff check src tests
	uv run ruff format --check src tests
	uv run mypy
	cd web && npm run lint

test: ## Unit, moto, API, MCP tests + RAG eval with coverage
	uv run pytest --cov

security: ## Bandit, pip-audit, npm audit
	uv run bandit -c pyproject.toml -r src -q
	uv export --frozen --no-dev --all-extras --no-hashes --no-emit-project > /tmp/req.txt && uv run pip-audit -r /tmp/req.txt
	cd web && npm audit --omit=dev --audit-level=high

check: lint test security ## Everything CI runs on Python/web code

scan: ## Scan the demo estate from the CLI
	DEMO_MODE=true uv run cloud-copilot scan --no-explain

mcp: ## Start the MCP server over stdio
	uv run cloud-copilot mcp

docker: ## Build the container image
	docker build -t $(IMAGE) .

up: ## Full local platform (app, Postgres, Prometheus, Grafana, MCP)
	docker compose up -d --build
	@echo "app http://localhost:8000 · grafana http://localhost:3000 · prometheus http://localhost:9090 · mcp http://localhost:8765/mcp"

down: ## Stop the local platform
	docker compose down

tf-check: ## terraform fmt + validate for every stack
	terraform fmt -check -recursive infra/terraform
	for d in infra/terraform/aws infra/terraform/azure infra/terraform/modules/*; do (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1; done

helm-check: ## helm lint + render
	helm dependency build deploy/helm/cloud-copilot
	helm lint deploy/helm/cloud-copilot --strict
	helm template t deploy/helm/cloud-copilot -f deploy/helm/cloud-copilot/values-demo.yaml > /dev/null

kind: docker ## Deploy the demo profile to a local kind cluster
	kind create cluster --name copilot || true
	kind load docker-image $(IMAGE) --name copilot
	helm dependency build deploy/helm/cloud-copilot
	helm upgrade --install cc deploy/helm/cloud-copilot -n cc --create-namespace -f deploy/helm/cloud-copilot/values-demo.yaml \
	  --set image.repository=cloud-copilot --set image.tag=local --set image.pullPolicy=Never --set postgresql.enabled=false --wait
	@echo "kubectl -n cc port-forward svc/cc-cloud-copilot 8000:80"

.PHONY: help install dev web-dev web-build lint test security check scan mcp docker up down tf-check helm-check kind docs

docs: ## Regenerate docs/rules.md from the rule registry
	uv run python scripts/gen_rules_doc.py
