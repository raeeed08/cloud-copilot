"""
Knowledge corpus for retrieval-augmented generation.

Two sources:
1. hand-written playbooks in ``knowledge/*.md`` (incident response, hardening guides, cost optimisation…)
2. one generated document per rule (rationale, remediation, Terraform, compliance mapping)

Documents are chunked on Markdown headings so each chunk is a self-contained answer unit with a stable,
citable id (``file#section``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from cloud_copilot.core.registry import RULES, load_all

MAX_CHARS = 1600


@dataclass(frozen=True)
class Chunk:
    id: str
    source: str
    title: str
    text: str
    tags: tuple[str, ...] = field(default_factory=tuple)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


def chunk_markdown(source: str, text: str, tags: tuple[str, ...] = ()) -> list[Chunk]:
    doc_title = source
    sections: list[tuple[str, list[str]]] = []
    current_title, buf = "", list[str]()
    for line in text.splitlines():
        if line.startswith("# "):
            doc_title = line[2:].strip()
            continue
        m = re.match(r"^(##+)\s+(.*)", line)
        if m:
            if buf and any(x.strip() for x in buf):
                sections.append((current_title, buf))
            current_title, buf = m.group(2).strip(), []
        else:
            buf.append(line)
    if buf and any(x.strip() for x in buf):
        sections.append((current_title, buf))

    chunks: list[Chunk] = []
    for title, lines in sections:
        body = "\n".join(lines).strip()
        full_title = f"{doc_title} — {title}" if title else doc_title
        # split oversized sections on paragraph boundaries
        parts, cur = [], ""
        for para in body.split("\n\n"):
            if len(cur) + len(para) > MAX_CHARS and cur:
                parts.append(cur)
                cur = ""
            cur = f"{cur}\n\n{para}" if cur else para
        if cur:
            parts.append(cur)
        for i, part in enumerate(parts):
            cid = f"{source}#{_slug(title) or 'intro'}" + (f"-{i + 1}" if len(parts) > 1 else "")
            chunks.append(Chunk(id=cid, source=source, title=full_title, text=part.strip(), tags=tags))
    return chunks


def rule_documents() -> list[Chunk]:
    load_all()
    out = []
    for r in RULES.values():
        i = r.info
        compliance = "; ".join(f"{k}: {', '.join(v)}" for k, v in i.compliance.items()) or "n/a"
        text = (
            f"Rule {i.id} ({i.provider.value.upper()} {i.service}, severity {i.severity.value}, "
            f"category {i.category.value}).\n\nWhy it matters: {i.description}\n\n"
            f"How to fix: {i.remediation}\n\nCompliance: {compliance}"
        )
        if i.terraform:
            text += f"\n\nTerraform example:\n```hcl\n{i.terraform}\n```"
        out.append(
            Chunk(
                id=f"rules/{i.id}",
                source=f"rules/{i.id}",
                title=f"{i.id} — {i.title}",
                text=text,
                tags=(i.provider.value, i.service, i.id),
            )
        )
    return out


def knowledge_dir(override: Path | None = None) -> Path | None:
    if override and override.exists():
        return override
    repo = Path(__file__).resolve().parents[3] / "knowledge"
    if repo.exists():
        return repo
    try:
        packaged = Path(str(resources.files("cloud_copilot") / "_knowledge"))
        return packaged if packaged.exists() else None
    except (ModuleNotFoundError, FileNotFoundError):
        return None


def load_corpus(directory: Path | None = None) -> list[Chunk]:
    chunks = rule_documents()
    root = knowledge_dir(directory)
    if root:
        for path in sorted(root.rglob("*.md")):
            rel = path.relative_to(root).with_suffix("").as_posix()
            chunks.extend(chunk_markdown(rel, path.read_text(encoding="utf-8"), tags=(rel.split("/")[0],)))
    return chunks
