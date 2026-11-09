"""Azure spend via Cost Management (last 30 days, grouped by service)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cloud_copilot.log import get_logger
from cloud_copilot.models import CostSummary, Provider
from cloud_copilot.providers.azure.context import AzureContext

log = get_logger(__name__)


def azure_costs(ctx: AzureContext) -> CostSummary | None:
    try:
        from azure.mgmt.costmanagement import CostManagementClient
    except ImportError:
        return None
    end = datetime.now(UTC)
    start = end - timedelta(days=30)
    client = CostManagementClient(ctx.credential)
    totals: dict[str, float] = {}
    currency = "USD"
    for sub in ctx.subscription_ids:
        try:
            result = client.query.usage(
                scope=f"/subscriptions/{sub}",
                parameters={
                    "type": "ActualCost",
                    "timeframe": "Custom",
                    "time_period": {"from": start.isoformat(), "to": end.isoformat()},
                    "dataset": {
                        "granularity": "None",
                        "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                        "grouping": [{"type": "Dimension", "name": "ServiceName"}],
                    },
                },
            )
        except Exception as exc:
            log.info("azure_cost_unavailable", subscription=sub, error=type(exc).__name__)
            continue
        cols = [c.name for c in result.columns]
        for row in result.rows:
            rec = dict(zip(cols, row, strict=False))
            name = str(rec.get("ServiceName", "other"))
            totals[name] = totals.get(name, 0.0) + float(rec.get("Cost", 0))
            currency = str(rec.get("Currency", currency))
    if not totals:
        return None
    return CostSummary(
        provider=Provider.AZURE,
        currency=currency,
        period_start=start.date().isoformat(),
        period_end=end.date().isoformat(),
        total=round(sum(totals.values()), 2),
        by_service=sorted(
            ({"service": k, "amount": round(v, 2)} for k, v in totals.items()), key=lambda x: -float(x["amount"])
        ),
    )
