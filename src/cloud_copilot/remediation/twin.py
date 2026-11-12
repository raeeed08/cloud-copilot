"""
Digital twin of a cloud estate, used to verify a fix *before* anyone applies it.

The twin is the normalised scanner output of one account (the same dicts the rules read). A fix is
expressed twice: as Terraform for humans, and as a **state patch**, the resource state the Terraform is
expected to produce. The patch is applied to a copy of the twin and every rule of the service is
re-evaluated, plus attack-path correlation across services. A fix is *verified* only if:

* the target finding disappears,
* no new finding appears anywhere in the service (no regression, e.g. fixing exposure by breaking logging),
* and, for an attack path, the scenario no longer correlates.

Rules are pure functions over data, so this is exact for what the scanner can observe, and costs
microseconds. When a proposed patch fails, ``search_fix`` explores small counterfactual edits
(boolean flips, list-item removal, values copied from compliant peer resources) and returns the
smallest verified one. It doubles as the offline planner when no LLM is configured.
"""

from __future__ import annotations

import copy
import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from cloud_copilot.core.correlation import correlate
from cloud_copilot.core.engine import evaluate
from cloud_copilot.core.registry import RULES, load_all, rules_for
from cloud_copilot.models import Finding, Provider

ID_KEYS = ("id", "arn", "resource_id", "name")
# Values that are frequently the compliant setting of a string field; tried after peer values.
SECURE_HINTS: tuple[Any, ...] = (
    "required",
    "Disabled",
    "Deny",
    "TLS1_2",
    "1.2",
    "Enabled",
    "enabled",
    "aws:kms",
    "Inactive",
    "Standard",
)
# Common compliant thresholds (password length, reuse history, retention days, key age…).
NUMERIC_HINTS: tuple[int, ...] = (14, 24, 90, 365, 0, 1)
META_KEYS = ("region", "account", "subscription", "tags", "location")
MAX_DEPTH = 3
MAX_PAIRS = 400

_PATH = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


# --------------------------------------------------------------------------- patches
def parse_path(path: str) -> list[str | int]:
    return [int(idx) if idx else key for key, idx in _PATH.findall(path)]


def _get(obj: Any, parts: list[str | int]) -> Any:
    for p in parts:
        obj = obj[p]
    return obj


def apply_ops(item: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a patched copy of one resource. Ops: ``set`` a value or ``remove`` a key/list item."""
    out = copy.deepcopy(item)

    def order(o: dict[str, Any]) -> tuple[bool, int]:
        last = parse_path(o["path"])[-1]
        return o["op"] == "remove", -(last if isinstance(last, int) else 0)

    # sets first, then removals from the highest list index down so earlier indices stay valid
    ordered = sorted(ops, key=order)
    for op in ordered:
        parts = parse_path(op["path"])
        if not parts:
            raise ValueError("empty path")
        parent = _get(out, parts[:-1])
        last = parts[-1]
        if op["op"] == "set":
            if isinstance(parent, list) and isinstance(last, int) and last >= len(parent):
                raise IndexError(op["path"])
            parent[last] = copy.deepcopy(op.get("value"))
        elif op["op"] == "remove":
            del parent[last]
        else:
            raise ValueError(f"unknown op {op['op']}")
    return out


@dataclass
class Locator:
    collection: str | None  # None = the service-level settings (account-wide resources)
    index: int | None
    key: str | None = None


def locate(data: dict[str, Any], resource_id: str, resource_name: str | None = None) -> Locator:
    """Find the resource dict a finding points to: by id, ARN or name, then by display name.

    Account-wide findings (no trail, no password policy, detector disabled…) use a synthetic id; their
    "resource" is the whole service document, so the fix can edit any part of it.
    """
    for wanted in (resource_id, resource_name):
        if not wanted:
            continue
        for coll, items in data.items():
            if not isinstance(items, list):
                continue
            for i, item in enumerate(items):
                if isinstance(item, dict):
                    for k in ID_KEYS:
                        if item.get(k) == wanted:
                            return Locator(coll, i, k)
    return Locator(None, None)


def resource_view(data: dict[str, Any], loc: Locator) -> dict[str, Any]:
    if loc.collection is None:
        return data
    return data[loc.collection][loc.index]  # type: ignore[index]


def patch_service(data: dict[str, Any], loc: Locator, ops: list[dict[str, Any]]) -> dict[str, Any]:
    if loc.collection is None:
        return apply_ops(data, ops)
    out = copy.deepcopy(data)
    out[loc.collection][loc.index] = apply_ops(data[loc.collection][loc.index], ops)  # type: ignore[index]
    return out


# --------------------------------------------------------------------------- verification
def evaluate_service(provider: Provider, service: str, data: dict[str, Any], account: str | None) -> list[Finding]:
    load_all()
    out: list[Finding] = []
    for r in rules_for(provider, service):
        try:
            out.extend(evaluate(r, data, account))
        except Exception:
            out.append(
                Finding(
                    id=f"rule-error:{r.info.id}",
                    rule_id=r.info.id,
                    title="rule error",
                    provider=provider,
                    service=service,
                    severity=r.info.severity,
                    category=r.info.category,
                    resource_id="*",
                    resource_name="*",
                    message="rule could not evaluate the patched state",
                    remediation="",
                )
            )
    return out


@dataclass
class TwinResult:
    verified: bool
    resolved: list[str] = field(default_factory=list)  # finding ids that disappear
    introduced: list[dict[str, str]] = field(default_factory=list)  # new findings (regressions)
    target_resolved: bool = False
    scenarios_broken: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class Twin:
    """Mutable copy of one account's scanner data, with verification of patches against all rules."""

    def __init__(
        self, provider: Provider, account: str | None, raw: dict[str, dict[str, Any]], findings: list[Finding]
    ) -> None:
        self.provider = provider
        self.account = account
        self.raw = copy.deepcopy(raw)  # service -> data
        self.findings = [f for f in findings if f.provider is provider and not f.suppressed]
        self.scenarios = self._correlate(self.raw, self.findings)

    def _correlate(self, raw: dict[str, Any], findings: list[Finding]) -> list[dict[str, Any]]:
        key = f"{self.provider.value}:{self.account or 'default'}"
        try:
            return correlate({key: raw}, findings)
        except Exception:
            return []

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def check(self, finding: Finding, ops: list[dict[str, Any]]) -> TwinResult:
        data = self.raw.get(finding.service)
        if data is None:
            return TwinResult(False, reason=f"service {finding.service} not in snapshot")
        loc = locate(data, finding.resource_id, finding.resource_name)
        try:
            patched = patch_service(data, loc, ops)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            return TwinResult(False, reason=f"patch does not apply: {type(exc).__name__}: {exc}")
        before = {f.id for f in self.findings if f.service == finding.service}
        after_findings = evaluate_service(self.provider, finding.service, patched, self.account)
        after = {f.id for f in after_findings}
        introduced = [
            {"rule_id": f.rule_id, "resource": f.resource_name, "message": f.message}
            for f in after_findings
            if f.id not in before
        ]
        resolved = sorted(before - after)
        target = finding.id not in after
        raw_after = {**self.raw, finding.service: patched}
        others = [f for f in self.findings if f.service != finding.service]
        open_after = {s["id"] for s in self._correlate(raw_after, others + after_findings)}
        broken = [s["id"] for s in self.scenarios if s["id"] not in open_after]
        verified = target and not introduced
        reason = (
            "fix verified"
            if verified
            else "target finding still present"
            if not target
            else f"introduces {len(introduced)} new finding(s)"
        )
        return TwinResult(verified, resolved, introduced, target, broken, reason)

    def commit(self, finding: Finding, ops: list[dict[str, Any]]) -> None:
        """Keep a verified patch in the twin so later fixes are checked against the fixed state."""
        data = self.raw[finding.service]
        self.raw[finding.service] = patch_service(data, locate(data, finding.resource_id, finding.resource_name), ops)
        self.findings = [f for f in self.findings if f.service != finding.service] + evaluate_service(
            self.provider, finding.service, self.raw[finding.service], self.account
        )
        self.scenarios = self._correlate(self.raw, self.findings)

    # ----------------------------------------------------------------------- fix search
    def candidates(self, finding: Finding) -> list[list[dict[str, Any]]]:
        data = self.raw[finding.service]
        loc = locate(data, finding.resource_id, finding.resource_name)
        item = resource_view(data, loc)
        failing = {f.resource_id for f in self.findings if f.rule_id == finding.rule_id}
        peers = []
        if loc.collection is not None:
            for other in data[loc.collection]:
                if (
                    other is not item
                    and isinstance(other, dict)
                    and not any(other.get(k) in failing for k in ID_KEYS if other.get(k))
                ):
                    peers.append(other)
        out: list[list[dict[str, Any]]] = []
        self._walk(item, "", peers, out, 0)
        return out

    def _walk(self, obj: Any, prefix: str, peers: list[dict[str, Any]], out: list, depth: int) -> None:
        if depth > MAX_DEPTH or not isinstance(obj, dict):
            return
        for key, value in obj.items():
            if key in ID_KEYS or key in META_KEYS:
                continue
            path = f"{prefix}.{key}" if prefix else key
            peer_values = []
            for p in peers:
                try:
                    pv = _get(p, parse_path(path))
                except (KeyError, IndexError, TypeError):
                    continue
                if pv != value and pv not in peer_values:
                    peer_values.append(pv)
            for pv in peer_values:
                out.append([{"op": "set", "path": path, "value": pv}])
            if isinstance(value, bool):
                out.append([{"op": "set", "path": path, "value": not value}])
            elif value is None:
                out.append([{"op": "set", "path": path, "value": True}])
            elif isinstance(value, str):
                out.extend([{"op": "set", "path": path, "value": h}] for h in SECURE_HINTS if h != value)
            elif isinstance(value, int):
                out.extend([{"op": "set", "path": path, "value": h}] for h in NUMERIC_HINTS if h != value)
            elif isinstance(value, dict):
                self._walk(value, path, peers, out, depth + 1)
            elif isinstance(value, list):
                if value and all(not isinstance(v, (dict, list)) for v in value):
                    out.append([{"op": "set", "path": path, "value": []}])
                for i, elem in enumerate(value[:20]):
                    if isinstance(elem, dict):
                        out.append([{"op": "remove", "path": f"{path}[{i}]"}])
                        self._walk(elem, f"{path}[{i}]", [], out, depth + 1)

    def search_fix(self, finding: Finding) -> tuple[list[dict[str, Any]], TwinResult] | None:
        """Smallest verified patch: single edits first, then pairs. ``set`` is preferred to ``remove``."""
        singles = self.candidates(finding)
        singles.sort(key=lambda ops: ops[0]["op"] == "remove")
        partial: list[list[dict[str, Any]]] = []
        for ops in singles:
            res = self.check(finding, ops)
            if res.verified:
                return ops, res
            if res.reason.startswith("target") and not res.introduced:
                partial.append(ops)
        for a, b in itertools.islice(itertools.combinations(partial or singles, 2), MAX_PAIRS):
            ops = a + b
            res = self.check(finding, ops)
            if res.verified:
                return ops, res
        return None


def rule_title(rule_id: str) -> str:
    load_all()
    return RULES[rule_id].info.title if rule_id in RULES else rule_id
