# 05: Docker & Compose

## Concepts
- **Image** = read-only layered filesystem + metadata (entrypoint, env, user). **Container** = a running
  instance with its own namespaces (pid, net, mnt…) and cgroups (CPU/memory limits).
- **Layers & cache**: each Dockerfile instruction makes a layer; a change invalidates that layer and everything
  after. So copy dependency manifests first, install, then copy source.
- **Registry**: GHCR, ECR, ACR, Docker Hub. Tag (`:2.1.0`, mutable) vs **digest** (`@sha256:…`, immutable).
  Deploy by digest in production.
- **BuildKit / buildx**: modern builder: parallel stages, cache mounts, multi-platform (amd64 + arm64), SBOM and
  provenance attestations.

## Our Dockerfile, line by line (`Dockerfile`)
1. **Stage `web`** (`node:22-alpine`): `npm ci` (lockfile-exact install) → `npm run build` → static assets.
2. **Stage `build`** (`python:3.12-slim` + uv): `uv sync --frozen --no-install-project` with only
   `pyproject.toml`/`uv.lock` copied: a **dependency layer cached** until the lockfile changes. Then copy `src/`,
   the built frontend and install the project. `--mount=type=cache` keeps uv's download cache between builds.
3. **Stage `runtime`**: fresh slim image, copies only the virtualenv and knowledge (no compilers, no Node, no
   source of other stages) → smaller and fewer CVEs.
   - **Non-root** user UID 10001, `USER 10001`.
   - OCI **labels** (source, version, revision) for traceability.
   - `HEALTHCHECK` hitting `/healthz`.
   - `ENTRYPOINT ["cloud-copilot"]` + `CMD ["serve", …]`: same image runs `scan`, `mcp`, `db-upgrade`.

**Multi-stage** = build tools stay in build stages; only artifacts reach runtime.

## Runtime hardening (Compose & Kubernetes do the same)
- `read_only: true` root filesystem + `tmpfs: /tmp` + a writable volume only where needed (`/app/data`).
- `cap_drop: [ALL]`, `security_opt: no-new-privileges`.
- No secrets in the image (`.dockerignore` excludes `.env`, `.git`, tests, infra). Secrets come from env vars or
  mounted files at runtime.

## Docker Compose (`docker-compose.yml`)
- Declarative multi-container app: `api`, `mcp`, `postgres`, `prometheus`, `grafana`, optional `ollama`, `jaeger`
  (**profiles**: `--profile local-llm`).
- **YAML anchors** (`x-app: &app`, `<<: *app`) share config between api and mcp.
- `depends_on: condition: service_healthy` waits for Postgres' healthcheck.
- **Named volumes** (`pg-data`, `app-data`) persist data across `docker compose down` (use `down -v` to wipe).
- Services reach each other by **service name** on the Compose network (`postgres:5432`, `api:8000`).

## Commands
```bash
docker build -t cloud-copilot:local .                     # (BuildKit needs the buildx plugin)
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/you/cloud-copilot:2.1.0 --push .
docker run --rm -p 8000:8000 -e DEMO_MODE=true cloud-copilot:local
docker run --rm cloud-copilot:local rules | head             # same image, other command
docker compose up -d --build        docker compose ps        docker compose logs -f api
docker compose exec postgres psql -U copilot -c 'select count(*) from findings'
docker compose down                 docker compose down -v   # -v also deletes volumes!
docker image inspect cloud-copilot:local --format '{{.Config.User}} {{.Size}}'
docker history cloud-copilot:local                         # see layers and their size
```
*Tip used in this project:* without the plugins installed locally, run them from an image:
`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:$PWD -w $PWD docker:27.4-cli docker compose up -d`.
(Mounting the Docker socket gives that container full control of the daemon. Fine on your laptop, never in prod.)

## Interview questions
1. **How do you make images small and secure?** Multi-stage, slim/distroless base, non-root, no build tools,
   `.dockerignore`, pinned versions, scan with Trivy, rebuild regularly for patches.
2. **CMD vs ENTRYPOINT?** ENTRYPOINT is the executable; CMD default arguments (overridable).
3. **Why order Dockerfile instructions carefully?** Layer cache: stable layers (deps) first, volatile (source) last.
4. **Tag vs digest?** Tags move; digests are content addresses. Deploy digests for reproducibility.
5. **Container vs VM?** Shared kernel with namespace/cgroup isolation vs full guest OS on a hypervisor.
6. **How do you pass secrets to a container?** Runtime env vars or mounted files from a secret manager (K8s Secret
   via External Secrets, Docker secrets); never `ENV`/`ARG` in the Dockerfile.

## Exercises
1. `docker history` the image and find the biggest layer. Why is it big? (Hint: Azure SDKs.) How could you build a
   slimmer AWS-only variant with a build arg?
2. Run the container with `--read-only` but without the tmpfs: what breaks and why?
3. Scan it: `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image cloud-copilot:local`.
