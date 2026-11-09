"""
Connected cloud accounts: turn a stored account (config + decrypted secret) into a scan context.

AWS auth methods
    assume_role   recommended: role ARN (+ external ID); base credentials = stored keys or the ambient chain
    access_keys   an IAM user's access key (fine for a lab, avoid in production)
    profile       a named profile from ~/.aws (local development)
    default       ambient chain: env vars, SSO cache, IRSA / Pod Identity, instance role
Azure auth methods
    service_principal   tenant + client ID + client secret (Reader roles)
    default             DefaultAzureCredential: az login, managed identity, workload identity
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_copilot.models import Provider
from cloud_copilot.providers.aws.context import AwsContext, NotConfiguredError, error_code

AWS_METHODS = {"assume_role", "access_keys", "profile", "default"}
AZURE_METHODS = {"service_principal", "default"}


class AccountError(ValueError):
    """Invalid account definition or credentials that don't work (message is safe to show)."""


def validate(provider: str, method: str, config: dict[str, Any], secret: dict[str, Any]) -> None:
    if provider == "aws":
        if method not in AWS_METHODS:
            raise AccountError(f"unknown AWS auth method {method}")
        if method == "assume_role" and not str(config.get("role_arn", "")).startswith("arn:aws"):
            raise AccountError("role_arn must look like arn:aws:iam::<account>:role/<name>")
        if method == "access_keys" and not (secret.get("access_key_id") and secret.get("secret_access_key")):
            raise AccountError("access_key_id and secret_access_key are required")
        if method == "profile" and not config.get("profile"):
            raise AccountError("profile is required")
    elif provider == "azure":
        if method not in AZURE_METHODS:
            raise AccountError(f"unknown Azure auth method {method}")
        if method == "service_principal" and not (
            config.get("tenant_id") and config.get("client_id") and secret.get("client_secret")
        ):
            raise AccountError("tenant_id, client_id and client_secret are required")
    else:
        raise AccountError(f"unknown provider {provider}")


# ----------------------------------------------------------------------------- AWS
def _aws_base_session(method: str, config: dict[str, Any], secret: dict[str, Any]) -> boto3.session.Session:
    region = config.get("home_region") or "us-east-1"
    if method == "profile":
        return boto3.session.Session(profile_name=config["profile"], region_name=region)
    if secret.get("access_key_id"):
        return boto3.session.Session(
            aws_access_key_id=secret["access_key_id"],
            aws_secret_access_key=secret["secret_access_key"],
            aws_session_token=secret.get("session_token") or None,
            region_name=region,
        )
    return boto3.session.Session(region_name=region)


def aws_session(method: str, config: dict[str, Any], secret: dict[str, Any]) -> boto3.session.Session:
    base = _aws_base_session(method, config, secret)
    if method != "assume_role":
        return base
    params: dict[str, Any] = {
        "RoleArn": config["role_arn"],
        "RoleSessionName": "cloud-copilot",
        "DurationSeconds": 3600,
    }
    if config.get("external_id"):
        params["ExternalId"] = config["external_id"]
    try:
        creds = base.client("sts").assume_role(**params)["Credentials"]
    except (ClientError, BotoCoreError) as exc:
        raise NotConfiguredError(f"cannot assume {config['role_arn']}: {error_code(exc)}") from exc
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=base.region_name,
    )


def aws_context(method: str, config: dict[str, Any], secret: dict[str, Any], max_workers: int = 8) -> AwsContext:
    regions = [r.strip() for r in config.get("regions", []) if r.strip()]
    return AwsContext(
        session=aws_session(method, config, secret),
        regions=regions,
        home_region=config.get("home_region") or "us-east-1",
        max_workers=max_workers,
    )


def verify_aws(method: str, config: dict[str, Any], secret: dict[str, Any]) -> dict[str, Any]:
    try:
        session = aws_session(method, config, secret)
        ident = session.client("sts").get_caller_identity()
    except NotConfiguredError as exc:
        raise AccountError(str(exc)) from exc
    except (ClientError, BotoCoreError) as exc:
        code = error_code(exc)
        hint = {
            "InvalidClientTokenId": "the access key does not exist or was deleted",
            "SignatureDoesNotMatch": "the secret access key is wrong",
            "ExpiredToken": "the session token expired",
        }.get(code, "")
        raise AccountError(f"AWS rejected the credentials ({code}){': ' + hint if hint else ''}") from exc
    alias = None
    try:
        aliases = session.client("iam").list_account_aliases().get("AccountAliases", [])
        alias = aliases[0] if aliases else None
    except (ClientError, BotoCoreError):
        pass
    account = ident["Account"]
    return {
        "account_id": account,
        "arn": ident["Arn"],
        "alias": alias,
        "console_url": f"https://{alias or account}.signin.aws.amazon.com/console",
    }


# ----------------------------------------------------------------------------- Azure
def azure_credential(method: str, config: dict[str, Any], secret: dict[str, Any]) -> Any:
    try:
        if method == "service_principal":
            from azure.identity import ClientSecretCredential

            return ClientSecretCredential(config["tenant_id"], config["client_id"], secret["client_secret"])
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential(exclude_interactive_browser_credential=True)
    except ImportError as exc:
        raise NotConfiguredError("Azure SDK not installed (pip install 'cloud-copilot[azure]')") from exc


def azure_context(method: str, config: dict[str, Any], secret: dict[str, Any]) -> Any:
    from cloud_copilot.providers.azure.context import AzureContext

    subs = [s.strip() for s in config.get("subscription_ids", []) if s.strip()]
    return AzureContext(subs, credential=azure_credential(method, config, secret))


def verify_azure(method: str, config: dict[str, Any], secret: dict[str, Any]) -> dict[str, Any]:
    try:
        from azure.mgmt.resource import SubscriptionClient

        cred = azure_credential(method, config, secret)
        subs = [
            {"id": s.subscription_id, "name": s.display_name, "tenant_id": getattr(s, "tenant_id", None)}
            for s in SubscriptionClient(cred).subscriptions.list()
        ]
    except NotConfiguredError as exc:
        raise AccountError(str(exc)) from exc
    except Exception as exc:  # azure-identity raises many credential error types
        msg = str(exc).split("\n")[0][:200]
        raise AccountError(f"Azure rejected the credentials ({type(exc).__name__}: {msg})") from exc
    wanted = set(config.get("subscription_ids") or [])
    if wanted:
        subs = [s for s in subs if s["id"] in wanted]
    if not subs:
        raise AccountError("credentials work but no subscription is visible: grant 'Reader' on a subscription")
    tenant = config.get("tenant_id") or subs[0].get("tenant_id") or ""
    return {
        "tenant_id": tenant,
        "subscriptions": subs,
        "console_url": f"https://portal.azure.com/#@{tenant}/resource/subscriptions/{subs[0]['id']}/overview",
    }


def verify(provider: str, method: str, config: dict[str, Any], secret: dict[str, Any]) -> dict[str, Any]:
    validate(provider, method, config, secret)
    return verify_aws(method, config, secret) if provider == "aws" else verify_azure(method, config, secret)


def build_context(provider: Provider, method: str, config: dict[str, Any], secret: dict[str, Any]) -> Any:
    if provider is Provider.AWS:
        ctx = aws_context(method, config, secret)
        _ = ctx.account_id  # fail fast
        return ctx
    ctx = azure_context(method, config, secret)
    _ = ctx.subscription_ids
    return ctx
