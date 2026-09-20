from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from wordshield.config import Settings
from wordshield.detectors import PrivacyFilterDetector, QwenDetector, RulesDetector
from wordshield.models import Block


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate local detectors on synthetic RU/EN text"
    )
    parser.add_argument("--qwen", action="store_true")
    parser.add_argument("--privacy-filter", action="store_true")
    args = parser.parse_args()
    cases = json.loads(
        (Path(__file__).parents[1] / "tests/fixtures/synthetic_cases.json").read_text()
    )
    blocks = [Block(c["id"], "synthetic", "paragraph", c["text"]) for c in cases]
    detections = RulesDetector().detect(blocks)
    settings = Settings.from_env()
    if args.qwen:
        detections += await QwenDetector(settings).detect(blocks)
    if args.privacy_filter:
        detections += await PrivacyFilterDetector(settings).detect(blocks)
    found = {(d.block_id, d.entity_type, d.exact_text) for d in detections}
    expected = {
        (c["id"], entity, text) for c in cases for entity, text in c["expected"]
    }
    neutral = {(c["id"], text) for c in cases for text in c["neutral"]}
    leaked_neutral = sorted(
        (bid, text) for bid, _, text in found if (bid, text) in neutral
    )
    missed = sorted(expected - found)
    print(
        json.dumps(
            {
                "expected": len(expected),
                "found_expected": len(expected) - len(missed),
                "recall": round(
                    (len(expected) - len(missed)) / max(1, len(expected)), 3
                ),
                "missed": missed,
                "neutral_selected": leaked_neutral,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
