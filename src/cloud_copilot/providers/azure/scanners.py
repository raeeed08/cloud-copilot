"""
Azure scanners. SDK imports stay inside functions so the package works without the [azure] extra.
Each ``normalise_*`` function turns an SDK model into a plain dict and is unit-tested with fakes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from cloud_copilot.core.registry import scanner
from cloud_copilot.models import Provider
from cloud_copilot.providers.azure.context import AzureContext, resource_group

AZ = Provider.AZURE
INTERNET = {"*", "internet", "0.0.0.0/0", "0.0.0.0", "::/0", "any"}  # nosec B104


def _per_subscription(ctx: AzureContext, label: str, fn: Callable[[str], Iterable[dict[str, Any]]]) -> list[dict]:
    out: list[dict[str, Any]] = []
    for sub in ctx.subscription_ids:
        try:
            for item in fn(sub):
                item.setdefault("subscription", sub)
                out.append(item)
        except Exception as exc:  # SDK raises HttpResponseError, ClientAuthenticationError, ...
            ctx.warnings.append(f"{label}@{sub}: {type(exc).__name__}: {str(exc)[:160]}")
    return out


def _g(obj: Any, *path: str, default: Any = None) -> Any:
    for p in path:
        if obj is None:
            return default
        obj = getattr(obj, p, None)
    return default if obj is None else obj


def _enum(v: Any) -> str | None:
    return None if v is None else str(getattr(v, "value", v))


# ----------------------------------------------------------------------------- Storage
def normalise_storage_account(a: Any) -> dict[str, Any]:
    https = _g(a, "enable_https_traffic_only")
    if https is None:
        https = _g(a, "supports_https_traffic_only", default=True)
    return {
        "id": a.id,
        "name": a.name,
        "resource_group": resource_group(a.id),
        "location": a.location,
        "allow_blob_public_access": bool(_g(a, "allow_blob_public_access", default=False)),
        "https_only": bool(https),
        "min_tls": _enum(_g(a, "minimum_tls_version")) or "TLS1_0",
        "shared_key_access": _g(a, "allow_shared_key_access", default=True) is not False,
        "network_default_action": _enum(_g(a, "network_rule_set", "default_action")) or "Allow",
        "public_network_access": _enum(_g(a, "public_network_access")) or "Enabled",
        "infrastructure_encryption": bool(_g(a, "encryption", "require_infrastructure_encryption", default=False)),
    }


@scanner(AZ, "storage", "Storage accounts")
def scan_storage(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.storage import StorageManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        client = StorageManagementClient(ctx.credential, s)
        return [normalise_storage_account(a) for a in client.storage_accounts.list()]

    return {"accounts": _per_subscription(ctx, "storage", sub)}


# ----------------------------------------------------------------------------- Network
def _ports(rule: Any) -> list[str]:
    ports = list(_g(rule, "destination_port_ranges", default=[]) or [])
    if _g(rule, "destination_port_range"):
        ports.append(rule.destination_port_range)
    return ports or ["*"]


def _sources(rule: Any) -> list[str]:
    srcs = list(_g(rule, "source_address_prefixes", default=[]) or [])
    if _g(rule, "source_address_prefix"):
        srcs.append(rule.source_address_prefix)
    return srcs


def normalise_nsg(nsg: Any) -> dict[str, Any]:
    rules = []
    for r in _g(nsg, "security_rules", default=[]) or []:
        if _enum(r.direction) != "Inbound" or _enum(r.access) != "Allow":
            continue
        sources = _sources(r)
        rules.append(
            {
                "name": r.name,
                "priority": r.priority,
                "protocol": _enum(r.protocol),
                "ports": _ports(r),
                "sources": sources,
                "from_internet": any(s.lower() in INTERNET for s in sources),
            }
        )
    return {
        "id": nsg.id,
        "name": nsg.name,
        "resource_group": resource_group(nsg.id),
        "location": nsg.location,
        "inbound_allow": rules,
    }


def port_in(port: int, spec: str) -> bool:
    spec = spec.strip()
    if spec in ("*", ""):
        return True
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    return spec == str(port)


@scanner(AZ, "network", "Network security groups and public IPs")
def scan_network(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.network import NetworkManagementClient

    def nsgs(s: str) -> Iterable[dict[str, Any]]:
        return [normalise_nsg(n) for n in NetworkManagementClient(ctx.credential, s).network_security_groups.list_all()]

    def ips(s: str) -> Iterable[dict[str, Any]]:
        return [
            {
                "id": ip.id,
                "name": ip.name,
                "resource_group": resource_group(ip.id),
                "location": ip.location,
                "associated": bool(ip.ip_configuration or _g(ip, "nat_gateway")),
                "sku": _enum(_g(ip, "sku", "name")) or "Basic",
            }
            for ip in NetworkManagementClient(ctx.credential, s).public_ip_addresses.list_all()
        ]

    return {"nsgs": _per_subscription(ctx, "nsg", nsgs), "public_ips": _per_subscription(ctx, "public-ip", ips)}


# ----------------------------------------------------------------------------- Key Vault
def normalise_vault(v: Any) -> dict[str, Any]:
    p = v.properties
    return {
        "id": v.id,
        "name": v.name,
        "resource_group": resource_group(v.id),
        "location": v.location,
        "soft_delete": _g(p, "enable_soft_delete", default=True) is not False,
        "purge_protection": bool(_g(p, "enable_purge_protection", default=False)),
        "rbac": bool(_g(p, "enable_rbac_authorization", default=False)),
        "public_network_access": _enum(_g(p, "public_network_access")) or "Enabled",
        "network_default_action": _enum(_g(p, "network_acls", "default_action")) or "Allow",
    }


@scanner(AZ, "keyvault", "Key Vaults")
def scan_keyvault(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.keyvault import KeyVaultManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        return [normalise_vault(v) for v in KeyVaultManagementClient(ctx.credential, s).vaults.list_by_subscription()]

    return {"vaults": _per_subscription(ctx, "keyvault", sub)}


# ----------------------------------------------------------------------------- SQL
@scanner(AZ, "sql", "Azure SQL logical servers")
def scan_sql(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.sql import SqlManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        client = SqlManagementClient(ctx.credential, s)
        out = []
        for srv in client.servers.list():
            rg = resource_group(srv.id)
            fw = [(r.start_ip_address, r.end_ip_address) for r in client.firewall_rules.list_by_server(rg, srv.name)]
            try:
                auditing = _enum(client.server_blob_auditing_policies.get(rg, srv.name).state) == "Enabled"
            except Exception:
                auditing = None
            out.append(
                {
                    "id": srv.id,
                    "name": srv.name,
                    "resource_group": rg,
                    "location": srv.location,
                    "public_network_access": _enum(_g(srv, "public_network_access")) or "Enabled",
                    "min_tls": _g(srv, "minimal_tls_version") or "None",
                    "allow_all_ips": any(a == "0.0.0.0" and b == "255.255.255.255" for a, b in fw),  # nosec B104
                    "allow_azure_services": ("0.0.0.0", "0.0.0.0") in fw,  # nosec B104
                    "aad_admin": _g(srv, "administrators") is not None,
                    "auditing": auditing,
                }
            )
        return out

    return {"servers": _per_subscription(ctx, "sql", sub)}


# ----------------------------------------------------------------------------- Compute
@scanner(AZ, "compute", "Virtual machines and managed disks")
def scan_compute(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.compute import ComputeManagementClient

    def disks(s: str) -> Iterable[dict[str, Any]]:
        return [
            {
                "id": d.id,
                "name": d.name,
                "resource_group": resource_group(d.id),
                "location": d.location,
                "state": _enum(d.disk_state),
                "size_gb": d.disk_size_gb or 0,
                "sku": _enum(_g(d, "sku", "name")),
                "network_access_policy": _enum(_g(d, "network_access_policy")) or "AllowAll",
                "encryption": _enum(_g(d, "encryption", "type")),
            }
            for d in ComputeManagementClient(ctx.credential, s).disks.list()
        ]

    def vms(s: str) -> Iterable[dict[str, Any]]:
        return [
            {
                "id": v.id,
                "name": v.name,
                "resource_group": resource_group(v.id),
                "location": v.location,
                "encryption_at_host": bool(_g(v, "security_profile", "encryption_at_host", default=False)),
                "secure_boot": bool(_g(v, "security_profile", "uefi_settings", "secure_boot_enabled", default=False)),
                "password_auth": not bool(
                    _g(v, "os_profile", "linux_configuration", "disable_password_authentication", default=True)
                ),
                "managed_identity": _g(v, "identity") is not None,
            }
            for v in ComputeManagementClient(ctx.credential, s).virtual_machines.list_all()
        ]

    return {"disks": _per_subscription(ctx, "disks", disks), "vms": _per_subscription(ctx, "vms", vms)}


# ----------------------------------------------------------------------------- App Service
@scanner(AZ, "appservice", "App Service / Function Apps")
def scan_appservice(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.web import WebSiteManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        client = WebSiteManagementClient(ctx.credential, s)
        out = []
        for app in client.web_apps.list():
            rg = resource_group(app.id)
            cfg = client.web_apps.get_configuration(rg, app.name)
            out.append(
                {
                    "id": app.id,
                    "name": app.name,
                    "resource_group": rg,
                    "location": app.location,
                    "kind": app.kind,
                    "https_only": bool(app.https_only),
                    "min_tls": _g(cfg, "min_tls_version") or "1.0",
                    "ftps_state": _enum(_g(cfg, "ftps_state")) or "AllAllowed",
                    "remote_debugging": bool(_g(cfg, "remote_debugging_enabled", default=False)),
                    "managed_identity": _g(app, "identity") is not None,
                }
            )
        return out

    return {"apps": _per_subscription(ctx, "appservice", sub)}


# ----------------------------------------------------------------------------- Monitor
@scanner(AZ, "monitor", "Subscription diagnostic settings and activity log alerts")
def scan_monitor(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.monitor import MonitorManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        client = MonitorManagementClient(ctx.credential, s)
        diag = list(client.subscription_diagnostic_settings.list())
        ops: set[str] = set()
        for alert in client.activity_log_alerts.list_by_subscription_id():
            if not _g(alert, "enabled", default=True):
                continue
            for cond in _g(alert, "condition", "all_of", default=[]) or []:
                if (_g(cond, "field") or "").lower() == "operationname" and _g(cond, "equals"):
                    ops.add(cond.equals.lower())
        return [{"id": f"/subscriptions/{s}", "diagnostic_settings": bool(diag), "alert_operations": sorted(ops)}]

    return {"subscriptions": _per_subscription(ctx, "monitor", sub)}


# ----------------------------------------------------------------------------- Defender
@scanner(AZ, "defender", "Microsoft Defender for Cloud plans")
def scan_defender(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.security import SecurityCenter

    def sub(s: str) -> Iterable[dict[str, Any]]:
        client = SecurityCenter(ctx.credential, s)
        try:
            pricings = client.pricings.list(scope_id=f"subscriptions/{s}")
        except TypeError:  # older SDK signature
            pricings = client.pricings.list()
        items = getattr(pricings, "value", pricings)
        return [{"id": f"/subscriptions/{s}", "plans": {p.name: _enum(p.pricing_tier) for p in items}}]

    return {"subscriptions": _per_subscription(ctx, "defender", sub)}


# ----------------------------------------------------------------------------- Containers
@scanner(AZ, "aks", "AKS clusters")
def scan_aks(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.containerservice import ContainerServiceClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        return [
            {
                "id": c.id,
                "name": c.name,
                "resource_group": resource_group(c.id),
                "location": c.location,
                "rbac": bool(_g(c, "enable_rbac", default=False)),
                "local_accounts_disabled": bool(_g(c, "disable_local_accounts", default=False)),
                "private": bool(_g(c, "api_server_access_profile", "enable_private_cluster", default=False)),
                "authorized_ranges": list(_g(c, "api_server_access_profile", "authorized_ip_ranges", default=[]) or []),
                "network_policy": _enum(_g(c, "network_profile", "network_policy")),
                "version": _g(c, "kubernetes_version"),
            }
            for c in ContainerServiceClient(ctx.credential, s).managed_clusters.list()
        ]

    return {"clusters": _per_subscription(ctx, "aks", sub)}


@scanner(AZ, "acr", "Container registries")
def scan_acr(ctx: AzureContext) -> dict[str, Any]:
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient

    def sub(s: str) -> Iterable[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "name": r.name,
                "resource_group": resource_group(r.id),
                "location": r.location,
                "admin_user": bool(r.admin_user_enabled),
                "public_network_access": _enum(_g(r, "public_network_access")) or "Enabled",
                "sku": _enum(_g(r, "sku", "name")),
            }
            for r in ContainerRegistryManagementClient(ctx.credential, s).registries.list()
        ]

    return {"registries": _per_subscription(ctx, "acr", sub)}
