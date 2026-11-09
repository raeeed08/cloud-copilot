# ADR 0002: FastAPI backend, React SPA, one container image

**Status:** accepted

## Context
v1 was a Flask app with a Tailwind CDN page and a separate legacy dashboard.

## Decision
FastAPI (typed, OpenAPI out of the box, Pydantic models shared with the engine) serves both the REST API and the
React build. One image runs the `serve`, `scan` (CronJob), `mcp` and `db-upgrade` commands.

## Consequences
- One artifact to build, scan, sign and promote.
- The CSP can be strict (`script-src 'self'`) because no third-party scripts are loaded.
- Frontend and backend release together. That's acceptable at this size.
