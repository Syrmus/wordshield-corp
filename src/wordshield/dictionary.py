"""Encrypted global rules. Session snapshots, not this mutable list, restore files."""
from __future__ import annotations

import json
import re
from uuid import uuid4

from .crypto import encrypt, decrypt
from .models import Finding

GLOBAL_ALIAS = re.compile(r"\[\[([A-Z_]+)-GLOB-(\d{3,})(?::[^\[\]\r\n]{1,80})?\]\]")


class DictionaryStore:
    def __init__(self, store):
        self.store = store
        with store._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS global_dictionary (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL)")

    def _load(self, c):
        row = c.execute("SELECT payload FROM global_dictionary WHERE id=1").fetchone()
        if not row:
            return {"entries": [], "reserved": [], "next": 1}
        return json.loads(decrypt(self.store.keys.master_key(), row[0], b"global-dictionary:v1"))

    def list(self):
        with self.store._conn() as c:
            return self._load(c)["entries"]

    def save(self, value: str, entity_type: str, enabled: bool = True,
             entry_id: str | None = None, alias: str = ""):
        from .service import ENTITY_TYPES
        if not value.strip() or len(value) > 2000 or "[[" in value or "]]" in value:
            raise ValueError("Укажите точное исходное значение длиной до 2000 символов без алиасов")
        if entity_type not in ENTITY_TYPES:
            raise ValueError("Неизвестный тип сущности")
        with self.store._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            payload = self._load(c)
            old = next((e for e in payload["entries"] if e["id"] == entry_id), None)
            if entry_id and not old:
                raise KeyError(entry_id)
            if any(e["value"] == value and e["id"] != entry_id for e in payload["entries"]):
                raise ValueError("Это точное значение уже есть в словаре")
            unchanged = old and old["value"] == value and old["entity_type"] == entity_type
            label = ''
            if alias and not GLOBAL_ALIAS.fullmatch(alias):
                label = alias.strip().strip('[]').strip()
                if not label or len(label)>80 or any(c in label for c in '[]\r\n'):
                    raise ValueError('Название замены: от 1 до 80 символов, без переноса строки')
                if unchanged and old.get('label') == label:
                    alias = old['alias']
                else:
                    alias = f"[[{entity_type}-GLOB-{payload['next']:03d}:{label}]]"
            if alias and not (GLOBAL_ALIAS.fullmatch(alias) and GLOBAL_ALIAS.fullmatch(alias)[1] == entity_type):
                raise ValueError("Замена должна иметь вид [[ТИП-GLOB-001]] и соответствовать типу")
            if alias and alias in payload["reserved"] and not (unchanged and old["alias"] == alias):
                raise ValueError("Этот алиас уже использовался. Выберите новый номер или оставьте поле пустым")
            if not alias:
                alias = old["alias"] if unchanged else f"[[{entity_type}-GLOB-{payload['next']:03d}]]"
                while not unchanged and alias in payload["reserved"]:
                    payload["next"] += 1
                    alias = f"[[{entity_type}-GLOB-{payload['next']:03d}]]"
            if alias not in payload["reserved"]:
                payload["reserved"].append(alias)
                payload["next"] += 1
            entry = {"id": entry_id or uuid4().hex, "value": value,
                     "entity_type": entity_type, "alias": alias, "enabled": enabled,
                     "label": label or (old.get('label','') if unchanged and old['alias']==alias else '')}
            payload["entries"] = [e for e in payload["entries"] if e["id"] != entry_id] + [entry]
            self._write(c, payload)
            return entry

    def _write(self, c, payload):
        sealed = encrypt(self.store.keys.master_key(), json.dumps(payload, ensure_ascii=False).encode(), b"global-dictionary:v1")
        c.execute("INSERT OR REPLACE INTO global_dictionary VALUES (1, ?)", (sealed,))

    def delete(self, entry_id):
        with self.store._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            payload = self._load(c)
            if not any(e["id"] == entry_id for e in payload["entries"]):
                raise KeyError(entry_id)
            payload["entries"] = [e for e in payload["entries"] if e["id"] != entry_id]
            self._write(c, payload)


def apply_dictionary(blocks, findings, entries):
    """Exact, case-sensitive, whole-word matching; longest dictionary phrase wins.

    Suppress a model span only when wholly covered by a dictionary span.
    Wider/partial model overlaps remain pending rather than leaking their remainder.
    """
    chosen = []
    for block in blocks:
        candidates = []
        for entry in entries:
            if not entry["enabled"]:
                continue
            value = entry["value"]
            pattern = (r"(?<!\w)" if value[0].isalnum() else "") + re.escape(value) + (r"(?!\w)" if value[-1].isalnum() else "")
            for m in re.finditer(pattern, block.text):
                candidates.append((m.start(), m.end(), entry))
        selected = []
        for start, end, entry in sorted(candidates, key=lambda x: (-(x[1]-x[0]), x[0], x[2]["id"])):
            if any(start < b and a < end for a, b, _ in selected):
                continue
            selected.append((start, end, entry))
        for start, end, entry in selected:
            for f in findings:
                if f.block_id != block.id or not (f.start < end and start < f.end):
                    continue
                f.status = "rejected" if start <= f.start and f.end <= end else "pending"
            chosen.append(Finding(f"dict-{entry['id']}-{block.id}-{start}", block.id, start, end,
                                  block.text[start:end], entry["entity_type"], ["global-dictionary"],
                                  "accepted", 1.0, block.text[max(0,start-45):end+45], entry["alias"]))
    return findings + chosen
