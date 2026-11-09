"""REST API: auth, scan lifecycle, findings, suppression, export, chat, headers, rate limiting."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from cloud_copilot.api.app import create_app
from cloud_copilot.config import Settings
from cloud_copilot.service import CopilotService


@pytest.fixture
def client(settings: Settings, scanned: CopilotService) -> Iterator[TestClient]:
    with TestClient(create_app(settings, scanned)) as c:
        yield c


def test_health_and_headers(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Request-ID"]
    assert client.get("/readyz").json() == {"status": "ready"}
    assert b"copilot_http_requests_total" in client.get("/metrics").content


def test_latest_scan_and_findings(client: TestClient) -> None:
    scan = client.get("/api/v1/scans/latest").json()
    assert scan["status"] == "succeeded" and scan["score"] is not None and scan["explanation"]
    assert scan["started_at"].endswith("+00:00")
    findings = client.get("/api/v1/findings").json()
    assert len(findings) == scan["summary"]["total"]
    crit = client.get("/api/v1/findings", params={"severity": "CRITICAL"}).json()
    assert crit and all(f["severity"] == "CRITICAL" for f in crit)
    az = client.get("/api/v1/findings", params={"provider": "azure", "service": "storage"}).json()
    assert az and all(f["provider"] == "azure" for f in az)
    assert client.get("/api/v1/findings", params={"q": "acme-public-assets"}).json()


def test_suppression_flow(client: TestClient) -> None:
    fid = client.get("/api/v1/findings", params={"severity": "CRITICAL"}).json()[0]["id"]
    assert client.put(f"/api/v1/findings/{fid}/suppression", json={"reason": "x"}).status_code == 422
    assert client.put(f"/api/v1/findings/{fid}/suppression", json={"reason": "accepted risk"}).status_code == 200
    assert client.get(f"/api/v1/findings/{fid}").json()["suppressed"] is True
    assert client.get("/api/v1/suppressions").json()[0]["finding_id"] == fid
    assert client.delete(f"/api/v1/findings/{fid}/suppression").status_code == 200
    assert client.get(f"/api/v1/findings/{fid}").json()["suppressed"] is False
    assert client.put("/api/v1/findings/nope/suppression", json={"reason": "abc"}).status_code == 404


def test_new_scan_lifecycle(client: TestClient) -> None:
    r = client.post("/api/v1/scans", json={"providers": ["azure"], "explain": False})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    for _ in range(100):
        status = client.get(f"/api/v1/scans/{scan_id}").json()["status"]
        if status not in ("queued", "running"):
            break
        time.sleep(0.05)
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "succeeded" and set(scan["summary"]["by_provider"]) == {"azure"}
    assert len(client.get("/api/v1/scans").json()) == 2
    assert len(client.get("/api/v1/trend").json()) == 2


def test_catalog_and_compliance(client: TestClient) -> None:
    rules = client.get("/api/v1/rules").json()
    assert len(rules) >= 100
    assert client.get("/api/v1/rules/S3-002").json()["severity"] == "CRITICAL"
    assert client.get("/api/v1/rules/NOPE").status_code == 404
    assert len(client.get("/api/v1/services").json()) >= 25
    fws = {f["framework"]: f for f in client.get("/api/v1/compliance").json()["frameworks"]}
    assert {"CIS AWS Foundations v3.0", "CIS Azure Foundations v2.0", "NIST 800-53 r5"} <= set(fws)
    controls = [c["control"] for c in fws["CIS AWS Foundations v3.0"]["controls"]]
    assert controls.index("1.4") < controls.index("1.10")  # natural sort


def test_exports(client: TestClient) -> None:
    csv = client.get("/api/v1/findings/export", params={"fmt": "csv"})
    assert csv.status_code == 200 and csv.text.startswith("id,severity,rule_id")
    md = client.get("/api/v1/findings/export", params={"fmt": "md"})
    assert md.text.startswith("# Cloud Copilot report")


def test_chat_offline_mode(client: TestClient) -> None:
    r = client.post("/api/v1/chat", json={"message": "How do I fix public S3 buckets?"}).json()
    assert r["mode"] == "offline" and r["citations"] and "S3-002" in r["answer"]
    assert client.post("/api/v1/chat", json={"message": ""}).status_code == 422
    hits = client.get("/api/v1/knowledge/search", params={"q": "compromised access key"}).json()
    assert hits[0]["id"].startswith("incident-response/aws-compromised-access-key")


def test_api_key_auth(settings: Settings, scanned: CopilotService) -> None:
    settings.api_keys = [SecretStr("s3cret")]
    with TestClient(create_app(settings, scanned)) as c:
        assert c.get("/api/v1/findings").status_code == 401
        assert c.get("/api/v1/findings", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/v1/findings", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert c.get("/api/v1/findings", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert c.get("/healthz").status_code == 200  # probes stay public
        assert c.get("/api/v1/info").json()["auth"] is True


def test_prod_requires_auth(settings: Settings, scanned: CopilotService) -> None:
    settings.environment = "prod"
    with pytest.raises(RuntimeError, match="API_KEYS"):
        create_app(settings, scanned)


def test_rate_limit(settings: Settings, scanned: CopilotService) -> None:
    settings.chat_rate_limit_per_minute = 2
    with TestClient(create_app(settings, scanned)) as c:
        codes = [c.post("/api/v1/chat", json={"message": "hi"}).status_code for _ in range(3)]
        assert codes == [200, 200, 429]


def test_concurrent_scan_conflict(client: TestClient, scanned: CopilotService) -> None:
    scanned._running = "busy"
    assert client.post("/api/v1/scans", json={}).status_code == 409
    scanned._running = None
