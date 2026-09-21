from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

EntityType = Literal[
    "PII",
    "PERSON",
    "ORG",
    "ADDRESS",
    "CITY",
    "EMAIL",
    "PHONE",
    "URL",
    "PRICE",
    "BANK",
    "TAX_ID",
    "REG_ID",
    "DOCUMENT_ID",
    "PASSPORT",
    "DATE",
    "TIME",
    "SECRET",
    "IP",
    "ACCOUNT",
]


@dataclass
class Block:
    id: str
    part: str
    kind: str
    text: str
    node_paths: list[str] = field(default_factory=list)


def hard_boundaries(block: Block) -> set[int]:
    """Offsets separated by a visible Word break without changing legacy text."""
    result: set[int] = set()
    prefix = "hard-boundary:"
    for item in block.node_paths:
        if not item.startswith(prefix):
            continue
        try:
            offset = int(item[len(prefix) :])
        except ValueError:
            continue
        if 0 < offset < len(block.text):
            result.add(offset)
    return result


@dataclass
class Finding:
    id: str
    block_id: str
    start: int
    end: int
    exact_text: str
    entity_type: EntityType
    sources: list[str]
    status: Literal["accepted", "pending", "rejected"]
    confidence: float
    context: str = ""
    alias: str | None = None

    def json(self) -> dict:
        return asdict(self)


@dataclass
class Detection:
    block_id: str
    start: int
    end: int
    exact_text: str
    entity_type: EntityType
    source: str
    confidence: float
    format_confirmed: bool = False
