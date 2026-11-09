"""Encrypted credentials, account lifecycle, real verification + scan against moto, AI provider settings."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from cloud_copilot.api.app import create_app
from cloud_copilot.config import Settings
from cloud_copilot.crypto import SecretBox, SecretBoxError, generate_key, mask
from cloud_copilot.providers.accounts import AccountError, validate
from cloud_copilot.service import CopilotService


def test_secretbox_roundtrip_and_tamper(tmp_path: Any) -> None:
    box = SecretBox(generate_key().encode())
    token = box.encrypt({"k": "super-secret-value"})
    assert "super-secret" not in token and box.decrypt(token) == {"k": "super-secret-value"}
    with pytest.raises(SecretBoxError):
        SecretBox(generate_key().encode()).decrypt(token)
    assert mask("AKIAABCDEFGHIJKLMNOP") == "…MNOP" and mask(None) is None


def test_dev_key_file_is_private(tmp_path: Any) -> None:
    s = Settings(_env_file=None, secret_key_file=str(tmp_path / "k.key"))  # type: ignore[call-arg]
    SecretBox.from_settings(s)
    assert oct((tmp_path / "k.key").stat().st_mode)[-3:] == "600"
    SecretBox.from_settings(s)  # reuses the same key


@pytest.mark.parametrize(
    ("provider", "method", "config", "secret", "msg"),
    [
        ("aws", "assume_role", {"role_arn": "nope"}, {}, "role_arn"),
        ("aws", "access_keys", {}, {"access_key_id": "AKIA"}, "required"),
        ("aws", "magic", {}, {}, "unknown"),
        ("azure", "service_principal", {"tenant_id": "t"}, {}, "required"),
        ("gcp", "x", {}, {}, "unknown provider"),
    ],
)
def test_validation(provider: str, method: str, config: dict, secret: dict, msg: str) -> None:
    with pytest.raises(AccountError, match=msg):
        validate(provider, method, config, secret)


@pytest.fixture
def client(settings: Settings, tmp_path: Any) -> Iterator[TestClient]:
    settings.secret_key_file = str(tmp_path / "secret.key")
    svc = CopilotService(settings)
    with TestClient(create_app(settings, svc)) as c:
        yield c
    svc._executor.shutdown(wait=True)


def _wait(c: TestClient, scan_id: str) -> dict[str, Any]:
    for _ in range(200):
        scan = c.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] not in ("queued", "running"):
            return scan
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_connect_and_scan_real_aws_account_with_moto(client: TestClient) -> None:
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="scanner")
        key = iam.create_access_key(UserName="scanner")["AccessKey"]
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="lab-unversioned")

        r = client.post(
            "/api/v1/accounts",
            json={
                "name": "Lab",
                "provider": "aws",
                "auth_method": "access_keys",
                "config": {"regions": ["us-east-1"]},
                "secret": {"access_key_id": key["AccessKeyId"], "secret_access_key": key["SecretAccessKey"]},
            },
        )
        assert r.status_code == 201, r.text
        acc = r.json()
        assert acc["status"] == "connected" and acc["identity"]["account_id"] == "123456789012"
        assert acc["identity"]["console_url"].startswith("https://")
        assert key["SecretAccessKey"] not in r.text and acc["secret_hints"]["access_key_id"].startswith("…")
        assert key["SecretAccessKey"] not in client.get("/api/v1/accounts").text

        scan = _wait(
            client, client.post("/api/v1/scans", json={"account_ids": [acc["id"]], "explain": False}).json()["id"]
        )
        assert scan["status"] in ("succeeded", "partial") and scan["demo"] is False
        assert scan["targets"] == [acc["id"]]
        assert any(k == "aws:123456789012" for k in scan["accounts"])
        findings = client.get("/api/v1/findings", params={"rule_id": "S3-005"}).json()
        s3 = [f for f in findings if f["resource_name"] == "lab-unversioned" and f["rule_id"] == "S3-005"]
        assert s3 and s3[0]["account"] == "123456789012" and "s3/buckets/lab-unversioned" in s3[0]["console_url"]
        assert client.get("/api/v1/plan").json()["phases"]

    assert client.delete(f"/api/v1/accounts/{acc['id']}").status_code == 200
    assert client.get("/api/v1/accounts").json() == []


def test_bad_credentials_are_reported_not_raised(client: TestClient) -> None:
    with mock_aws():
        r = client.post(
            "/api/v1/accounts",
            json={
                "name": "Broken",
                "provider": "aws",
                "auth_method": "assume_role",
                "config": {"role_arn": "arn:aws:iam::123456789012:role/does-not-exist"},
            },
        )
    assert r.status_code == 201
    assert r.json()["status"] in ("error", "connected")  # moto may allow assume_role on unknown roles
    assert (
        client.post("/api/v1/accounts", json={"name": "x", "provider": "aws", "auth_method": "access_keys"}).status_code
        == 422
    )


def test_llm_settings_lifecycle(client: TestClient, settings: Settings) -> None:
    base = client.get("/api/v1/settings/llm").json()
    assert base["configured"] is False and "groq" in base["presets"]
    r = client.put("/api/v1/settings/llm", json={"provider": "groq", "api_key": "gsk_test_1234567890abcd"})
    body = r.json()
    assert body["configured"] and body["provider"] == "groq" and body["key_hint"] == "…abcd"
    assert "gsk_test" not in r.text and body["base_url"] == "https://api.groq.com/openai/v1"
    assert body["models"][0] == "llama-3.3-70b-versatile"
    svc: CopilotService = client.app.state.service  # type: ignore[attr-defined]
    assert svc.copilot.gateway.config.provider == "groq" and svc.copilot.gateway.available  # live reload
    # keep the stored key when the field is omitted
    assert client.put("/api/v1/settings/llm", json={"provider": "groq", "language": "French"}).json()["has_key"]
    assert svc.copilot.language == "French"
    assert client.get("/api/v1/info").json()["llm_provider"] == "groq"
    assert client.put("/api/v1/settings/llm", json={"provider": "custom"}).status_code == 422
    assert client.delete("/api/v1/settings/llm").json()["source"] == "none"


def test_llm_test_endpoint_unconfigured(client: TestClient) -> None:
    assert client.post("/api/v1/settings/llm/test").json() == {
        "ok": False,
        "error": "Not configured: choose a provider and paste an API key.",
    }


def test_docs_page_csp_allows_swagger(client: TestClient) -> None:
    r = client.get("/api/docs")
    assert "cdn.jsdelivr.net" in r.headers["content-security-policy"]
    assert "cdn.jsdelivr.net" not in client.get("/healthz").headers["content-security-policy"]


def test_greeting_is_not_a_findings_dump(client: TestClient) -> None:
    _wait(client, client.post("/api/v1/scans", json={"demo": True, "explain": False}).json()["id"])
    ans = client.post("/api/v1/chat", json={"message": "hi"}).json()
    assert ans["answer"].startswith("Hi! I'm Cloud Copilot") and "attack path" in ans["answer"]
    assert "Most relevant findings" not in ans["answer"]


def test_fix_then_rescan_shows_resolved(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from cloud_copilot.providers import demo

    first = _wait(client, client.post("/api/v1/scans", json={"demo": True, "explain": False}).json()["id"])
    original = demo.data

    def fixed(provider: Any, service: str) -> dict[str, Any]:
        data = original(provider, service)
        if service == "rds":
            for i in data["instances"]:
                i["public"] = False
        return data

    monkeypatch.setattr(demo, "data", fixed)
    second = _wait(client, client.post("/api/v1/scans", json={"demo": True, "explain": False}).json()["id"])
    diff = client.get(f"/api/v1/scans/{second['id']}/diff").json()
    assert diff["previous_scan_id"] == first["id"]
    assert [r["rule_id"] for r in diff["resolved"]] == ["RDS-001"]
    assert second["score"] > first["score"]
    plan = client.get("/api/v1/plan").json()
    assert plan["resolved_since_last_scan"] == 1
    assert not any("reporting-pg exposed" in s["title"] for s in plan["scenarios"])
