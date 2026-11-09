# Connecting AI agents through MCP

## Claude Desktop / Cursor / any stdio client
```json
{
  "mcpServers": {
    "cloud-copilot": {
      "command": "uv",
      "args": ["--directory", "/path/to/cloud-copilot", "run", "cloud-copilot", "mcp"],
      "env": { "DEMO_MODE": "true" }
    }
  }
}
```

## Claude Code
```bash
claude mcp add cloud-copilot -- uv --directory /path/to/cloud-copilot run cloud-copilot mcp
```

## Remote agents (streamable HTTP)
`docker compose up mcp` (or `mcp.enabled=true` in Helm) exposes `http://<host>:8765/mcp`.

## Try it
> "Use cloud-copilot to triage my posture: what are the five most urgent fixes, with Terraform?"

The server exposes 9 tools (`get_posture_summary`, `list_findings`, `get_finding`, `get_rule`, `list_rules`,
`search_knowledge`, `get_compliance_status`, `get_cost_overview`, `run_scan`), 2 resources
(`copilot://scan/latest`, `copilot://rules`) and a `triage` prompt. Every tool except `run_scan` is annotated
read-only.
