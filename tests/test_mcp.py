"""MCP server: tool catalogue, annotations and calls against a scanned demo estate."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from cloud_copilot.mcp.server import build_server


def _payload(result: Any) -> Any:
    return json.loads(result.content[0].text)


def test_tools_and_annotations(scanned: Any) -> None:
    server = build_server(scanned)
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert {
        "get_posture_summary",
        "list_findings",
        "get_finding",
        "get_rule",
        "search_knowledge",
        "get_compliance_status",
        "get_cost_overview",
        "run_scan",
    } <= set(tools)
    assert tools["list_findings"].annotations.read_only_hint is True
    assert tools["run_scan"].annotations.read_only_hint is False


def test_tool_calls(scanned: Any) -> None:
    server = build_server(scanned)
    summary = _payload(asyncio.run(server.call_tool("get_posture_summary", {})))
    assert summary["score"] is not None and summary["summary"]["total"] > 0

    crit = asyncio.run(server.call_tool("list_findings", {"severity": "critical", "limit": 5}))
    first = _payload(crit)
    finding = first[0] if isinstance(first, list) else first
    detail = _payload(asyncio.run(server.call_tool("get_finding", {"finding_id": finding["id"]})))
    assert detail["remediation"]

    cost = _payload(asyncio.run(server.call_tool("get_cost_overview", {})))
    assert cost["estimated_monthly_savings"] > 0 and cost["top_opportunities"]

    rule = _payload(asyncio.run(server.call_tool("get_rule", {"rule_id": "IAM-001"})))
    assert rule["severity"] == "CRITICAL"
