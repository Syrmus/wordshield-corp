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


def text_segments(block: Block):
    cuts = [0, *sorted(hard_boundaries(block)), len(block.text)]
    return [(a, b) for a, b in zip(cuts, cuts[1:]) if a < b]


def inference_view(block: Block) -> tuple[Block, list[int | None]]:
    """Readable model text with legacy-compatible persistent offsets."""
    from dataclasses import replace
    text, offsets = [], []
    for index, (a, b) in enumerate(text_segments(block)):
        if index:
            text.append('\n')
            offsets.append(None)
        text.append(block.text[a:b])
        offsets.extend(range(a, b))
    return replace(block, text=''.join(text), node_paths=[]), offsets


def map_detection(block: Block, detection: Detection) -> list[Detection]:
    """Split at visible breaks without dropping model findings."""
    from dataclasses import replace
    view, offsets = inference_view(block)
    if not 0 <= detection.start < detection.end <= len(view.text) or view.text[detection.start:detection.end] != detection.exact_text:
        raise ValueError('Detector offsets do not match inference text')
    groups: list[list[int]] = []
    for offset in offsets[detection.start:detection.end]:
        if offset is None:
            groups.append([])
        else:
            if not groups:
                groups.append([])
            groups[-1].append(offset)
    return [replace(detection, start=g[0], end=g[-1]+1,
                    exact_text=block.text[g[0]:g[-1]+1]) for g in groups if g]
