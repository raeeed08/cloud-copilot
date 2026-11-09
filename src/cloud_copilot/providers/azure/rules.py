"""Azure rules. Same contract as AWS: pure functions over normalised scanner output."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloud_copilot.core.registry import Hit, rule
from cloud_copilot.models import Category, Provider, Severity
from cloud_copilot.providers.azure.scanners import port_in

AZ = Provider.AZURE
TLS_OK = {"TLS1_2", "TLS1_3", "1.2", "1.3"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
DATA_PORTS = {
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2375: "Docker API",
    6443: "Kubernetes API",
}
DISK_GB_MONTH = {
    "Premium_LRS": 0.15,
    "StandardSSD_LRS": 0.075,
    "Standard_LRS": 0.045,
    "UltraSSD_LRS": 0.12,
    "PremiumV2_LRS": 0.12,
}
CRITICAL_OPERATIONS = {
    "microsoft.authorization/policyassignments/write": "Create policy assignment",
    "microsoft.authorization/policyassignments/delete": "Delete policy assignment",
    "microsoft.network/networksecuritygroups/write": "Create/update NSG",
    "microsoft.network/networksecuritygroups/delete": "Delete NSG",
    "microsoft.network/networksecuritygroups/securityrules/write": "Create/update NSG rule",
    "microsoft.sql/servers/firewallrules/write": "Create/update SQL firewall rule",
    "microsoft.security/securitysolutions/write": "Create/update security solution",
}
DEFENDER_PLANS = ["VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults", "Containers", "Arm"]


def _h(r: dict[str, Any], msg: str, **kw: Any) -> Hit:
    return Hit(r["id"], msg, resource_name=r["name"], region=r.get("location"), account=r.get("subscription"), **kw)


# ----------------------------------------------------------------------------- Storage
STORAGE_TF = (
    'resource "azurerm_storage_account" "{resource}" {\n  # ...\n'
    '  https_traffic_only_enabled       = true\n  min_tls_version                  = "TLS1_2"\n'
    "  allow_nested_items_to_be_public  = false\n  shared_access_key_enabled        = false\n"
    '  public_network_access_enabled    = false\n  network_rules {\n    default_action = "Deny"\n'
    "  }\n}"
)


@rule(
    id="AZ-STOR-001",
    title="Storage account allows public blob access",
    provider=AZ,
    service="storage",
    severity=Severity.HIGH,
    description="Containers can be made anonymously readable from the internet.",
    remediation="Set allowBlobPublicAccess=false on the account.",
    cis=["3.7"],
    nist=["AC-3", "AC-21"],
    terraform=STORAGE_TF,
)
def stor_public(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["accounts"]:
        if a["allow_blob_public_access"]:
            yield _h(a, f"Storage account '{a['name']}' allows anonymous blob access.")


@rule(
    id="AZ-STOR-002",
    title="Storage account accepts HTTP",
    provider=AZ,
    service="storage",
    severity=Severity.MEDIUM,
    description="Data can travel unencrypted.",
    remediation="Enable 'Secure transfer required'.",
    cis=["3.1"],
    nist=["SC-8"],
    terraform=STORAGE_TF,
)
def stor_https(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["accounts"]:
        if not a["https_only"]:
            yield _h(a, f"Storage account '{a['name']}' does not require secure transfer.")


@rule(
    id="AZ-STOR-003",
    title="Storage account allows TLS < 1.2",
    provider=AZ,
    service="storage",
    severity=Severity.MEDIUM,
    description="TLS 1.0/1.1 are deprecated and vulnerable.",
    remediation="Set minimum TLS version to TLS1_2.",
    cis=["3.15"],
    nist=["SC-8", "SC-13"],
    terraform=STORAGE_TF,
)
def stor_tls(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["accounts"]:
        if a["min_tls"] not in TLS_OK:
            yield _h(a, f"Storage account '{a['name']}' accepts {a['min_tls']}.")


@rule(
    id="AZ-STOR-004",
    title="Storage account shared key access enabled",
    provider=AZ,
    service="storage",
    severity=Severity.LOW,
    description="Account keys are all-powerful, never expire and are hard to audit. Entra ID auth is preferred.",
    remediation="Disable shared key access after migrating clients to Entra ID / managed identity.",
    nist=["IA-2", "AC-6"],
    terraform=STORAGE_TF,
)
def stor_shared_key(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["accounts"]:
        if a["shared_key_access"]:
            yield _h(a, f"Storage account '{a['name']}' allows shared key authorisation.")


@rule(
    id="AZ-STOR-005",
    title="Storage account open to all networks",
    provider=AZ,
    service="storage",
    severity=Severity.MEDIUM,
    description="With default action Allow and public network access on, the data plane is reachable from any IP.",
    remediation="Set network default action to Deny and use private endpoints or selected networks.",
    cis=["3.8"],
    nist=["SC-7"],
    terraform=STORAGE_TF,
)
def stor_network(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["accounts"]:
        if a["public_network_access"] == "Enabled" and a["network_default_action"] == "Allow":
            yield _h(a, f"Storage account '{a['name']}' accepts traffic from all networks.")


# ----------------------------------------------------------------------------- Network
def _nsg_exposed(nsg: dict[str, Any], ports: dict[int, str]) -> list[str]:
    hits = set()
    for r in nsg["inbound_allow"]:
        if not r["from_internet"]:
            continue
        for port, label in ports.items():
            if any(port_in(port, spec) for spec in r["ports"]):
                hits.add(f"{label} ({port})")
    return sorted(hits)


NSG_TF = (
    'resource "azurerm_network_security_rule" "restricted" {\n  name                        = "allow-https"\n'
    '  network_security_group_name = "{resource}"\n  priority                    = 100\n'
    '  direction                   = "Inbound"\n  access                      = "Allow"\n'
    '  protocol                    = "Tcp"\n  destination_port_range      = "443"\n'
    '  source_address_prefix       = "203.0.113.0/24" # trusted range\n'
    '  destination_address_prefix  = "*"\n  source_port_range           = "*"\n'
    '  resource_group_name         = "<rg>"\n}'
)


@rule(
    id="AZ-NSG-001",
    title="Admin ports open to the internet",
    provider=AZ,
    service="network",
    severity=Severity.CRITICAL,
    description="SSH/RDP from Internet/any is brute-forced continuously.",
    remediation="Remove the rule; use Azure Bastion or Just-In-Time VM access.",
    cis=["6.1", "6.2"],
    nist=["SC-7", "AC-17"],
    terraform=NSG_TF,
)
def nsg_admin(d: dict[str, Any]) -> Iterator[Hit]:
    for n in d["nsgs"]:
        ports = _nsg_exposed(n, ADMIN_PORTS)
        if ports:
            yield _h(n, f"NSG '{n['name']}' exposes {', '.join(ports)} to the internet.", details={"ports": ports})


@rule(
    id="AZ-NSG-002",
    title="Database/cluster ports open to the internet",
    provider=AZ,
    service="network",
    severity=Severity.CRITICAL,
    description="Data services must not be reachable from the internet.",
    remediation="Restrict to the application subnet or use private endpoints.",
    nist=["SC-7"],
    terraform=NSG_TF,
)
def nsg_data(d: dict[str, Any]) -> Iterator[Hit]:
    for n in d["nsgs"]:
        ports = _nsg_exposed(n, DATA_PORTS)
        if ports:
            yield _h(n, f"NSG '{n['name']}' exposes {', '.join(ports)} to the internet.", details={"ports": ports})


@rule(
    id="AZ-NSG-003",
    title="NSG allows any port from the internet",
    provider=AZ,
    service="network",
    severity=Severity.HIGH,
    description="An allow-any rule from Internet removes the network boundary.",
    remediation="Replace with explicit ports behind Application Gateway / Front Door.",
    nist=["SC-7"],
    terraform=NSG_TF,
)
def nsg_any(d: dict[str, Any]) -> Iterator[Hit]:
    for n in d["nsgs"]:
        if any(
            r["from_internet"] and any(port_in(1, s) and port_in(65535, s) for s in r["ports"])
            for r in n["inbound_allow"]
        ):
            yield _h(n, f"NSG '{n['name']}' allows all ports from the internet.")


@rule(
    id="AZ-COST-001",
    title="Unassociated public IP",
    provider=AZ,
    service="network",
    severity=Severity.LOW,
    category=Category.COST,
    description="Standard public IPs are billed even when unused.",
    remediation="Delete the public IP if it is not reserved for a planned use.",
)
def idle_ip(d: dict[str, Any]) -> Iterator[Hit]:
    for ip in d["public_ips"]:
        if not ip["associated"]:
            yield _h(ip, f"Public IP '{ip['name']}' is not associated.", monthly_savings=3.65)


# ----------------------------------------------------------------------------- Key Vault
@rule(
    id="AZ-KV-001",
    title="Key Vault purge protection disabled",
    provider=AZ,
    service="keyvault",
    severity=Severity.MEDIUM,
    description="Without purge protection a deleted vault and its keys can be permanently destroyed, which "
    "is ransomware's favourite move.",
    remediation="Enable purge protection (irreversible).",
    cis=["8.5"],
    nist=["CP-9", "SC-12"],
    terraform='resource "azurerm_key_vault" "{resource}" {\n  # ...\n  purge_protection_enabled   = true\n'
    "  soft_delete_retention_days = 90\n  enable_rbac_authorization  = true\n"
    "  public_network_access_enabled = false\n}",
)
def kv_purge(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vaults"]:
        if not v["purge_protection"] or not v["soft_delete"]:
            yield _h(v, f"Key Vault '{v['name']}' can be permanently purged.")


@rule(
    id="AZ-KV-002",
    title="Key Vault uses access policies instead of RBAC",
    provider=AZ,
    service="keyvault",
    severity=Severity.LOW,
    description="Azure RBAC gives central, auditable and PIM-compatible permissions.",
    remediation="Migrate to the Azure RBAC permission model.",
    cis=["8.6"],
    nist=["AC-2", "AC-6"],
)
def kv_rbac(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vaults"]:
        if not v["rbac"]:
            yield _h(v, f"Key Vault '{v['name']}' uses legacy access policies.")


@rule(
    id="AZ-KV-003",
    title="Key Vault reachable from all networks",
    provider=AZ,
    service="keyvault",
    severity=Severity.MEDIUM,
    description="Secrets endpoints should be private.",
    remediation="Disable public network access and use private endpoints.",
    cis=["8.7"],
    nist=["SC-7"],
)
def kv_network(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vaults"]:
        if v["public_network_access"] == "Enabled" and v["network_default_action"] == "Allow":
            yield _h(v, f"Key Vault '{v['name']}' accepts traffic from all networks.")


# ----------------------------------------------------------------------------- SQL
@rule(
    id="AZ-SQL-001",
    title="SQL server firewall allows all IPs",
    provider=AZ,
    service="sql",
    severity=Severity.CRITICAL,
    description="A 0.0.0.0–255.255.255.255 rule exposes the database to the whole internet.",
    remediation="Delete the rule; use private endpoints or specific client IPs.",
    cis=["4.1.2"],
    nist=["SC-7"],
)
def sql_any(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["servers"]:
        if s["allow_all_ips"]:
            yield _h(s, f"SQL server '{s['name']}' allows connections from any IP.")


@rule(
    id="AZ-SQL-002",
    title="SQL server allows all Azure services",
    provider=AZ,
    service="sql",
    severity=Severity.MEDIUM,
    description="'Allow Azure services' admits any tenant's Azure resources, not just yours.",
    remediation="Remove the 0.0.0.0 rule and use VNet rules or private endpoints.",
    nist=["SC-7"],
)
def sql_azure_services(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["servers"]:
        if s["allow_azure_services"]:
            yield _h(s, f"SQL server '{s['name']}' allows access from all Azure services.")


@rule(
    id="AZ-SQL-003",
    title="SQL server auditing disabled",
    provider=AZ,
    service="sql",
    severity=Severity.MEDIUM,
    description="Auditing records database events for threat detection and compliance.",
    remediation="Enable server auditing to Log Analytics or a storage account.",
    cis=["4.1.1"],
    nist=["AU-2", "AU-12"],
)
def sql_audit(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["servers"]:
        if s["auditing"] is False:
            yield _h(s, f"SQL server '{s['name']}' has auditing disabled.")


@rule(
    id="AZ-SQL-004",
    title="SQL server without Entra ID admin",
    provider=AZ,
    service="sql",
    severity=Severity.LOW,
    description="Entra ID authentication enables MFA, conditional access and central de-provisioning.",
    remediation="Configure an Entra ID administrator (group) on the server.",
    cis=["4.1.4"],
    nist=["IA-2"],
)
def sql_aad(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["servers"]:
        if not s["aad_admin"]:
            yield _h(s, f"SQL server '{s['name']}' has no Entra ID administrator.")


@rule(
    id="AZ-SQL-005",
    title="SQL server accepts TLS < 1.2",
    provider=AZ,
    service="sql",
    severity=Severity.MEDIUM,
    description="Old TLS versions are deprecated.",
    remediation="Set minimal TLS version to 1.2.",
    nist=["SC-8"],
)
def sql_tls(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["servers"]:
        if s["min_tls"] not in TLS_OK:
            yield _h(s, f"SQL server '{s['name']}' minimal TLS is {s['min_tls']}.")


# ----------------------------------------------------------------------------- Compute
@rule(
    id="AZ-VM-001",
    title="Linux VM allows password authentication",
    provider=AZ,
    service="compute",
    severity=Severity.MEDIUM,
    description="Passwords can be brute-forced. SSH keys or Entra ID login can't.",
    remediation="Set disable_password_authentication=true and use SSH keys / Entra ID login.",
    nist=["IA-5"],
)
def vm_password(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vms"]:
        if v["password_auth"]:
            yield _h(v, f"VM '{v['name']}' allows SSH password authentication.")


@rule(
    id="AZ-VM-002",
    title="VM encryption at host disabled",
    provider=AZ,
    service="compute",
    severity=Severity.LOW,
    description="Encryption at host also encrypts temp disks and caches, end to end.",
    remediation="Enable encryption at host (requires feature registration).",
    nist=["SC-28"],
)
def vm_host_encryption(d: dict[str, Any]) -> Iterator[Hit]:
    for v in d["vms"]:
        if not v["encryption_at_host"]:
            yield _h(v, f"VM '{v['name']}' does not use encryption at host.")


@rule(
    id="AZ-DISK-001",
    title="Managed disk exportable from any network",
    provider=AZ,
    service="compute",
    severity=Severity.MEDIUM,
    description="networkAccessPolicy=AllowAll lets anyone with a SAS export the disk over the internet.",
    remediation="Set network access policy to DenyAll or AllowPrivate.",
    nist=["AC-3", "SC-7"],
)
def disk_network(d: dict[str, Any]) -> Iterator[Hit]:
    for disk in d["disks"]:
        if disk["network_access_policy"] == "AllowAll":
            yield _h(disk, f"Disk '{disk['name']}' can be exported from any network.")


@rule(
    id="AZ-COST-002",
    title="Unattached managed disk",
    provider=AZ,
    service="compute",
    severity=Severity.LOW,
    category=Category.COST,
    description="Unattached disks are billed every month.",
    remediation="Snapshot if needed and delete the disk.",
)
def disk_unattached(d: dict[str, Any]) -> Iterator[Hit]:
    for disk in d["disks"]:
        if disk["state"] == "Unattached":
            cost = round(disk["size_gb"] * DISK_GB_MONTH.get(disk["sku"] or "", 0.05), 2)
            yield _h(
                disk,
                f"Disk '{disk['name']}' ({disk['size_gb']} GiB {disk['sku']}) is unattached.",
                monthly_savings=cost,
            )


# ----------------------------------------------------------------------------- App Service
@rule(
    id="AZ-APP-001",
    title="App Service allows HTTP",
    provider=AZ,
    service="appservice",
    severity=Severity.MEDIUM,
    description="Without HTTPS-only, sessions can be intercepted.",
    remediation="Enable HTTPS Only.",
    cis=["9.2"],
    nist=["SC-8"],
    terraform='resource "azurerm_linux_web_app" "{resource}" {\n  # ...\n  https_only = true\n'
    '  site_config {\n    minimum_tls_version = "1.2"\n    ftps_state          = "Disabled"\n'
    "    remote_debugging_enabled = false\n  }\n}",
)
def app_https(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["apps"]:
        if not a["https_only"]:
            yield _h(a, f"App '{a['name']}' accepts plain HTTP.")


@rule(
    id="AZ-APP-002",
    title="App Service allows TLS < 1.2",
    provider=AZ,
    service="appservice",
    severity=Severity.MEDIUM,
    description="Old TLS versions are deprecated.",
    remediation="Set minimum TLS version to 1.2.",
    cis=["9.3"],
    nist=["SC-8"],
)
def app_tls(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["apps"]:
        if a["min_tls"] not in TLS_OK:
            yield _h(a, f"App '{a['name']}' accepts TLS {a['min_tls']}.")


@rule(
    id="AZ-APP-003",
    title="App Service allows plain FTP",
    provider=AZ,
    service="appservice",
    severity=Severity.MEDIUM,
    description="FTP sends deployment credentials in clear text.",
    remediation="Set FTPS state to Disabled (or FtpsOnly).",
    cis=["9.10"],
    nist=["SC-8"],
)
def app_ftp(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["apps"]:
        if a["ftps_state"] == "AllAllowed":
            yield _h(a, f"App '{a['name']}' allows unencrypted FTP.")


@rule(
    id="AZ-APP-004",
    title="App Service remote debugging enabled",
    provider=AZ,
    service="appservice",
    severity=Severity.HIGH,
    description="Remote debugging opens extra ports and should never stay on.",
    remediation="Disable remote debugging.",
    nist=["CM-7"],
)
def app_debug(d: dict[str, Any]) -> Iterator[Hit]:
    for a in d["apps"]:
        if a["remote_debugging"]:
            yield _h(a, f"App '{a['name']}' has remote debugging enabled.")


# ----------------------------------------------------------------------------- Monitor & Defender
@rule(
    id="AZ-MON-001",
    title="No subscription diagnostic setting",
    provider=AZ,
    service="monitor",
    severity=Severity.HIGH,
    description="Activity logs are kept only 90 days and aren't exported to a SIEM without a diagnostic setting.",
    remediation="Export the Activity Log to a Log Analytics workspace (and/or storage).",
    cis=["5.1.1"],
    nist=["AU-2", "AU-11"],
    terraform='resource "azurerm_monitor_diagnostic_setting" "activity" {\n  name = "activity-to-law"\n'
    '  target_resource_id         = "{resource}"\n'
    '  log_analytics_workspace_id = "<workspace-id>"\n'
    '  enabled_log { category = "Administrative" }\n  enabled_log { category = "Security" }\n'
    '  enabled_log { category = "Policy" }\n  enabled_log { category = "Alert" }\n}',
)
def mon_diag(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["subscriptions"]:
        if not s["diagnostic_settings"]:
            yield Hit(
                s["id"],
                "Activity Log is not exported by a diagnostic setting.",
                resource_name=s["id"],
                account=s.get("subscription"),
            )


@rule(
    id="AZ-MON-002",
    title="Missing activity log alerts for critical operations",
    provider=AZ,
    service="monitor",
    severity=Severity.MEDIUM,
    description="Changes to policies, NSGs and SQL firewalls should alert the security team in real time.",
    remediation="Create activity log alerts for each critical operation.",
    cis=["5.2.1", "5.2.3", "5.2.4"],
    nist=["SI-4", "AU-6"],
)
def mon_alerts(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["subscriptions"]:
        missing = [label for op, label in CRITICAL_OPERATIONS.items() if op not in s["alert_operations"]]
        if missing:
            yield Hit(
                f"{s['id']}/activity-alerts",
                f"No alert for {len(missing)} critical operation(s): "
                f"{', '.join(missing[:4])}{'…' if len(missing) > 4 else ''}.",
                resource_name=s["id"],
                account=s.get("subscription"),
                details={"missing": missing},
            )


@rule(
    id="AZ-DEF-001",
    title="Defender for Cloud plan on Free tier",
    provider=AZ,
    service="defender",
    severity=Severity.MEDIUM,
    description="Free tier only gives posture recommendations, with no threat detection for workloads.",
    remediation="Enable the Standard tier for the listed Defender plans.",
    cis=["2.1.1"],
    nist=["SI-4", "RA-5"],
)
def defender(d: dict[str, Any]) -> Iterator[Hit]:
    for s in d["subscriptions"]:
        free = [p for p in DEFENDER_PLANS if (s["plans"].get(p) or "Free") == "Free"]
        if free:
            yield Hit(
                f"{s['id']}/defender",
                f"Defender plans on Free tier: {', '.join(free)}.",
                resource_name=s["id"],
                account=s.get("subscription"),
                details={"plans": free},
            )


# ----------------------------------------------------------------------------- Containers
@rule(
    id="AZ-AKS-001",
    title="AKS API server publicly reachable",
    provider=AZ,
    service="aks",
    severity=Severity.HIGH,
    description="The Kubernetes API is exposed to the whole internet.",
    remediation="Use a private cluster or set authorized IP ranges.",
    nist=["SC-7", "AC-17"],
)
def aks_public(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        if not c["private"] and not c["authorized_ranges"]:
            yield _h(c, f"AKS cluster '{c['name']}' API server is open to any IP.")


@rule(
    id="AZ-AKS-002",
    title="AKS local accounts enabled",
    provider=AZ,
    service="aks",
    severity=Severity.MEDIUM,
    description="Local admin kubeconfigs bypass Entra ID and can't be revoked per user.",
    remediation="Enable Entra ID integration and disable local accounts.",
    nist=["IA-2", "AC-2"],
)
def aks_local(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        if not c["local_accounts_disabled"]:
            yield _h(c, f"AKS cluster '{c['name']}' still allows local accounts.")


@rule(
    id="AZ-AKS-003",
    title="AKS without network policy",
    provider=AZ,
    service="aks",
    severity=Severity.MEDIUM,
    description="Without a network policy engine every pod can talk to every other pod.",
    remediation="Enable Azure/Calico/Cilium network policy and default-deny namespaces.",
    nist=["SC-7", "AC-4"],
)
def aks_netpol(d: dict[str, Any]) -> Iterator[Hit]:
    for c in d["clusters"]:
        if not c["network_policy"]:
            yield _h(c, f"AKS cluster '{c['name']}' has no network policy engine.")


@rule(
    id="AZ-ACR-001",
    title="ACR admin user enabled",
    provider=AZ,
    service="acr",
    severity=Severity.MEDIUM,
    description="The admin user is a shared, static credential with push/pull rights.",
    remediation="Disable the admin user; use managed identities or scoped tokens.",
    nist=["IA-2", "AC-6"],
)
def acr_admin(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["registries"]:
        if r["admin_user"]:
            yield _h(r, f"Registry '{r['name']}' has the admin user enabled.")


@rule(
    id="AZ-ACR-002",
    title="ACR public network access enabled",
    provider=AZ,
    service="acr",
    severity=Severity.LOW,
    description="Registries should be reachable only from build agents and clusters.",
    remediation="Disable public network access (Premium SKU) and use private endpoints.",
    nist=["SC-7"],
)
def acr_public(d: dict[str, Any]) -> Iterator[Hit]:
    for r in d["registries"]:
        if r["public_network_access"] == "Enabled":
            yield _h(r, f"Registry '{r['name']}' is reachable from the internet.")
