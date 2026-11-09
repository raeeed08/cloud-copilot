"""Regenerate docs/rules.md from the rule registry (single source of truth)."""

from collections import defaultdict
from pathlib import Path
from typing import Any

from cloud_copilot.core.registry import RULES, SCANNERS, load_all


def main() -> None:
    load_all()
    by: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for r in RULES.values():
        by[(r.info.provider.value, r.info.service)].append(r.info)
    lines = [
        "# Rule catalogue",
        "",
        f"_Generated from the rule registry: **{len(RULES)} rules** across **{len(SCANNERS)} services**. "
        "Regenerate with `make docs`._",
        "",
        "Severity weights for the posture score: CRITICAL 10 · HIGH 6 · MEDIUM 3 · LOW 1 "
        "(cost & INFO rules are not scored). Compliance mappings are indicative.",
        "",
    ]
    for prov in ("aws", "azure"):
        lines += [f"## {'AWS' if prov == 'aws' else 'Azure'}", ""]
        for (p, svc), infos in sorted(by.items()):
            if p != prov:
                continue
            lines += [
                f"### {svc}",
                "",
                "| ID | Severity | Category | Title | CIS | NIST 800-53 |",
                "|---|---|---|---|---|---|",
            ]
            for i in sorted(infos, key=lambda x: x.id):
                cis = next((", ".join(v) for k, v in i.compliance.items() if k.startswith("CIS")), "")
                nist = ", ".join(i.compliance.get("NIST 800-53 r5", []))
                lines.append(f"| `{i.id}` | {i.severity.value} | {i.category.value} | {i.title} | {cis} | {nist} |")
            lines.append("")
    Path("docs/rules.md").write_text("\n".join(lines))
    print(f"{len(RULES)} rules documented")


if __name__ == "__main__":
    main()
