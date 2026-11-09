"""AWS spend via Cost Explorer (last 30 days by service + month-end forecast)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from cloud_copilot.log import get_logger
from cloud_copilot.models import CostSummary, Provider
from cloud_copilot.providers.aws.context import AwsContext, error_code

log = get_logger(__name__)


def aws_costs(ctx: AwsContext) -> CostSummary | None:
    ce = ctx.client("ce", "us-east-1")
    end = datetime.now(UTC).date()
    start = end - timedelta(days=30)
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except (ClientError, BotoCoreError) as exc:
        log.info("aws_cost_unavailable", error=error_code(exc))
        return None

    by_service: dict[str, float] = {}
    currency = "USD"
    for period in resp.get("ResultsByTime", []):
        for g in period.get("Groups", []):
            m = g["Metrics"]["UnblendedCost"]
            currency = m.get("Unit", currency)
            by_service[g["Keys"][0]] = by_service.get(g["Keys"][0], 0.0) + float(m["Amount"])

    forecast = None
    month_end = (end.replace(day=1) + timedelta(days=32)).replace(day=1)
    if end < month_end - timedelta(days=1):
        try:
            f = ce.get_cost_forecast(
                TimePeriod={"Start": (end + timedelta(days=1)).isoformat(), "End": month_end.isoformat()},
                Metric="UNBLENDED_COST",
                Granularity="MONTHLY",
            )
            forecast = round(float(f["Total"]["Amount"]), 2)
        except (ClientError, BotoCoreError):
            forecast = None

    items: list[dict[str, Any]] = sorted(
        ({"service": k, "amount": round(v, 2)} for k, v in by_service.items() if v > 0.005),
        key=lambda x: -float(x["amount"]),
    )
    return CostSummary(
        provider=Provider.AWS,
        currency=currency,
        period_start=start.isoformat(),
        period_end=end.isoformat(),
        total=round(sum(by_service.values()), 2),
        forecast_month_end=forecast,
        by_service=items,
    )
