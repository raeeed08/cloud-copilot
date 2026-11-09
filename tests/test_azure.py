"""Azure normalisers (with SDK-shaped fakes) and rules."""

from types import SimpleNamespace as NS
from typing import Any

import pytest

from cloud_copilot.core.registry import RULES, load_all
from cloud_copilot.providers.azure.context import resource_group
from cloud_copilot.providers.azure.scanners import normalise_nsg, normalise_storage_account, normalise_vault, port_in

load_all()
RID = "/subscriptions/s/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg"


def rule(direction: str = "Inbound", access: str = "Allow", **kw: Any) -> NS:
    base = {
        "name": "r",
        "priority": 100,
        "protocol": "Tcp",
        "direction": direction,
        "access": access,
        "source_address_prefix": None,
        "source_address_prefixes": [],
        "destination_port_range": None,
        "destination_port_ranges": [],
    }
    return NS(**(base | kw))


@pytest.mark.parametrize(
    ("port", "spec", "expected"),
    [
        (22, "22", True),
        (22, "*", True),
        (22, "1-65535", True),
        (22, "1000-2000", False),
        (3389, "3000-4000", True),
        (22, "abc", False),
    ],
)
def test_port_in(port: int, spec: str, expected: bool) -> None:
    assert port_in(port, spec) is expected


def test_nsg_plural_fields_are_considered() -> None:
    # v1 bug: only the singular fields were read
    nsg = NS(
        id=RID,
        name="nsg",
        location="westeurope",
        security_rules=[
            rule(source_address_prefixes=["10.0.0.0/8", "Internet"], destination_port_ranges=["443", "3389"]),
            rule(direction="Outbound", source_address_prefix="*", destination_port_range="22"),
        ],
    )
    data = normalise_nsg(nsg)
    assert data["resource_group"] == "rg-app"
    assert len(data["inbound_allow"]) == 1 and data["inbound_allow"][0]["from_internet"]
    hits = list(RULES["AZ-NSG-001"].fn({"nsgs": [data]}))
    assert hits and "RDP (3389)" in hits[0].message


def test_nsg_wide_range_from_any_is_flagged_as_any_port() -> None:
    data = normalise_nsg(
        NS(
            id=RID,
            name="nsg",
            location="x",
            security_rules=[rule(source_address_prefix="*", destination_port_range="1-65535")],
        )
    )
    assert list(RULES["AZ-NSG-003"].fn({"nsgs": [data]}))
    assert list(RULES["AZ-NSG-002"].fn({"nsgs": [data]}))


def test_storage_normaliser_handles_sdk_versions() -> None:
    acct = NS(
        id=RID,
        name="st",
        location="we",
        allow_blob_public_access=None,
        enable_https_traffic_only=None,
        supports_https_traffic_only=False,
        minimum_tls_version=NS(value="TLS1_0"),
        allow_shared_key_access=None,
        network_rule_set=NS(default_action="Deny"),
        public_network_access="Enabled",
        encryption=None,
    )
    d = normalise_storage_account(acct)
    assert d["https_only"] is False and d["min_tls"] == "TLS1_0" and d["shared_key_access"] is True
    assert d["allow_blob_public_access"] is False and d["network_default_action"] == "Deny"
    assert list(RULES["AZ-STOR-002"].fn({"accounts": [d]})) and list(RULES["AZ-STOR-003"].fn({"accounts": [d]}))
    assert list(RULES["AZ-STOR-005"].fn({"accounts": [d]})) == []


def test_vault_defaults() -> None:
    v = NS(
        id=RID,
        name="kv",
        location="we",
        properties=NS(
            enable_soft_delete=None,
            enable_purge_protection=None,
            enable_rbac_authorization=True,
            public_network_access=None,
            network_acls=None,
        ),
    )
    d = normalise_vault(v)
    assert d["soft_delete"] and not d["purge_protection"] and d["rbac"]
    assert list(RULES["AZ-KV-001"].fn({"vaults": [d]}))


def test_monitor_alerts_partial() -> None:
    sub = {
        "id": "/subscriptions/x",
        "diagnostic_settings": True,
        "alert_operations": ["microsoft.network/networksecuritygroups/write"],
    }
    (hit,) = RULES["AZ-MON-002"].fn({"subscriptions": [sub]})
    assert len(hit.details["missing"]) == 6
    assert list(RULES["AZ-MON-001"].fn({"subscriptions": [sub]})) == []


def test_resource_group_parsing() -> None:
    assert resource_group(RID) == "rg-app"
    assert resource_group("/subscriptions/s/resourcegroups/lower/providers/x") == "lower"
    assert resource_group(None) == ""
