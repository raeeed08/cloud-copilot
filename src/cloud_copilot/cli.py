"""Command-line interface: scan, serve, mcp, rules, ask."""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer

from cloud_copilot.config import get_settings
from cloud_copilot.log import configure_logging
from cloud_copilot.models import Provider, Severity

app = typer.Typer(help="Cloud Copilot: multi-cloud security & cost posture.", no_args_is_help=True)

SEV_ORDER = [s.value for s in Severity]


@app.command()
def scan(
    provider: Annotated[list[Provider] | None, typer.Option("--provider", "-p")] = None,
    output: Annotated[str, typer.Option("--output", "-o", help="table|json")] = "table",
    fail_on: Annotated[str | None, typer.Option(help="Exit 1 if a finding >= this severity exists (CI gate)")] = None,
    explain: Annotated[bool, typer.Option(help="Generate the AI executive summary")] = True,
) -> None:
    """Run a scan, store it, print the result."""
    from cloud_copilot.service import CopilotService

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    svc = CopilotService(settings)
    scan_id, result = svc.run_scan_sync(provider or None, trigger="cli", explain=explain)
    active = [f for f in result.findings if not f.suppressed]
    if output == "json":
        typer.echo(result.model_dump_json(indent=2))
    else:
        typer.echo(
            f"\nScan {scan_id}  status={result.status.value}  score={result.score}  "
            f"findings={len(active)}  demo={result.demo}"
        )
        for s in result.services:
            if s.status.value != "ok":
                typer.echo(f"  ! {s.provider.value}:{s.service} {s.status.value} {s.error or ''}")
        typer.echo("")
        for f in active:
            typer.echo(f"  [{f.severity.value:<8}] {f.rule_id:<12} {f.resource_name[:40]:<40} {f.message[:80]}")
        if result.explanation:
            typer.echo("\n" + result.explanation)
    if fail_on:
        threshold = SEV_ORDER.index(fail_on.upper())
        if any(SEV_ORDER.index(f.severity.value) <= threshold for f in active):
            raise typer.Exit(1)


@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000, workers: int = 1, reload: bool = False) -> None:  # noqa: S104  # nosec B104
    """Start the API + dashboard."""
    import uvicorn

    uvicorn.run(
        "cloud_copilot.api.main:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_config=None,
    )


@app.command()
def mcp(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8765) -> None:
    """Start the MCP server (stdio for desktop clients, http for remote agents)."""
    from cloud_copilot.mcp.server import run

    run(transport, host, port)


@app.command()
def rules(provider: Provider | None = None, as_json: bool = False) -> None:
    """List every rule."""
    from cloud_copilot.core.registry import RULES, load_all

    load_all()
    items = [r.info for r in RULES.values() if provider is None or r.info.provider is provider]
    if as_json:
        typer.echo(json.dumps([i.model_dump(mode="json") for i in items], indent=2))
        return
    for i in items:
        typer.echo(f"{i.id:<14} {i.severity.value:<9} {i.provider.value:<6} {i.service:<15} {i.title}")
    typer.echo(f"\n{len(items)} rules", err=True)


@app.command()
def ask(question: str) -> None:
    """Ask the copilot about the latest scan."""
    from cloud_copilot.service import CopilotService

    ans = CopilotService().ask(question)
    typer.echo(ans["answer"])
    if ans["citations"]:
        typer.echo("\nSources: " + ", ".join(c["id"] for c in ans["citations"]), err=True)


def main() -> None:  # pragma: no cover
    app(sys.argv[1:])


@app.command("db-upgrade")
def db_upgrade() -> None:
    """Apply database migrations (used by the Helm pre-upgrade hook)."""
    from cloud_copilot.store.db import Database

    Database(get_settings().database_url).migrate()
    typer.echo("database at head")
