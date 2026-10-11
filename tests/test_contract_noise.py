import pytest

from wordshield.detectors import merge_detections
from wordshield.models import Block, Detection


def findings(text, value, kind="PERSON", source="privacy-filter",
             part="word/document.xml", block_kind="paragraph"):
    block = Block("b", part, block_kind, text)
    start = text.index(value)
    return merge_detections([block], [Detection(
        "b", start, start + len(value), value, kind, source, .95,
    )])


@pytest.mark.parametrize("text,value", [
    ("received from the Lender, in full", "Lender"),
    ('LENDER: ______ (hereinafter the “Lender”).', "LENDER"),
    ('hereinafter the “Lender”', "Lender"),
    ("BORROWER: IVAN PETROV, an individual", "BORROWER"),
    ("until the Lender shall retain ownership", "Lender"),
    ("Кредитор: Иван Петров", "Кредитор"),
    ('именуемый далее «Заёмщик»', "Заёмщик"),
])
@pytest.mark.parametrize("source", ["privacy-filter", "gliner-ru"])
def test_contract_roles_are_not_names(text, value, source):
    assert findings(text, value, source=source) == []


@pytest.mark.parametrize("text,value,kind", [
    ("BORROWER: IVAN PETROV", "IVAN PETROV", "PERSON"),
    ("the Lender Holdings Ltd", "Lender Holdings Ltd", "ORG"),
    ("the Lender Holdings Ltd", "Lender", "PERSON"),
    ("Name: Lender", "Lender", "PERSON"),
    ("John Lender", "Lender", "PERSON"),
    ("Кредитор: Иван Петров", "Иван Петров", "PERSON"),
])
def test_names_and_companies_survive(text, value, kind):
    assert any(f.exact_text == value for f in findings(text, value, kind))


@pytest.mark.parametrize("value,prop", [("12090", "Words"), ("10424", "Characters"), ("336", "Pages")])
@pytest.mark.parametrize("source", ["gliner-ru", "privacy-filter"])
def test_only_known_word_counters_are_excluded(value, prop, source):
    assert findings(value, value, "PII", source, "docProps/app.xml", "property:" + prop) == []
    for part, kind in [("word/document.xml", "paragraph"),
                       ("docProps/custom.xml", "property:" + prop),
                       ("docProps/app.xml", "property:Company")]:
        assert findings(value, value, "PII", source, part, kind)


def test_explicit_rule_is_not_overridden():
    assert findings("Lender: ____", "Lender", source="rules")


def test_non_numeric_counter_is_not_silently_ignored():
    assert findings("Ivan Petrov", "Ivan Petrov", part="docProps/app.xml", block_kind="property:Words")
