import pytest

from wordshield.detectors import RulesDetector, merge_detections, expand_approved_repetitions
from wordshield.models import Block, Detection


def detected(text, spans):
    block = Block("b", "word/document.xml", "paragraph", text)
    ds = RulesDetector().detect([block])
    for value, kind, source in spans:
        start = text.index(value)
        ds.append(Detection(block.id, start, start+len(value), value, kind, source, .9))
    return block, merge_detections([block], ds)


@pytest.mark.parametrize("name", [
    "Соколов Иван Петрович", "Соколовой Анне Петровне",
    "Орлов-Денисов Пётр Ильич", "Кузнецова Мария Ильинична",
])
def test_complete_gliner_name_is_accepted(name):
    _, fs = detected("Сторона: " + name + ".", [(name, "PERSON", "gliner-ru")])
    assert next(f for f in fs if f.exact_text == name).status == "accepted"


def test_three_capitalised_words_are_not_enough():
    name = "Главное Управление Документации"
    _, fs = detected(name, [(name, "PERSON", "gliner-ru")])
    assert fs[0].status == "pending"


def test_known_initials_auto_accept_but_user_rejection_is_preserved():
    name, initials = "Соколов Иван Петрович", "Соколов И.П."
    block, fs = detected(name + "; подпись: " + initials,
                         [(name, "PERSON", "gliner-ru"), (initials, "PERSON", "gliner-ru")])
    assert next(f for f in fs if f.exact_text == initials).status == "pending"
    expanded = expand_approved_repetitions([block], fs)
    assert next(f for f in expanded if f.exact_text == initials).status == "accepted"
    next(f for f in fs if f.exact_text == initials).status = "rejected"
    protected = expand_approved_repetitions([block], fs)
    assert next(f for f in protected if f.exact_text == initials).status == "rejected"


@pytest.mark.parametrize("value", ["4516 № 654321", "45 16 № 654321", "4516654321"])
def test_passport_number_auto_accepts_without_label_or_issuer(value):
    _, fs = detected("Паспорт: " + value + ", выдан ГУ МВД России.",
                     [("654321", "DOCUMENT_ID", "gliner-ru")])
    assert any(f.exact_text == value and f.entity_type == "PASSPORT" and f.status == "accepted" for f in fs)
    assert not any(f.status == "accepted" and "Паспорт:" in f.exact_text for f in fs)


def test_complete_contract_number_wins_over_false_date_suffix():
    number = "AB-0034/26"
    _, fs = detected("Contract # " + number + ".", [("4/26", "DATE", "privacy-filter")])
    assert any(f.exact_text == number and f.status == "accepted" for f in fs)
    assert not any(f.exact_text == "4/26" and f.status != "rejected" for f in fs)


def test_public_law_date_does_not_reject_nearby_personal_date():
    law, birth = "27.07.2006", "21.03.1987"
    _, fs = detected("Федерального закона от " + law + " № 152-ФЗ; дата рождения: " + birth,
                     [(law, "DATE", "privacy-filter"), (birth, "DATE", "privacy-filter")])
    assert next(f for f in fs if f.exact_text == law).status == "rejected"
    assert next(f for f in fs if f.exact_text == birth).status != "rejected"


def test_unclear_legal_reference_still_requires_review():
    value = "27.07.2006"
    _, fs = detected("Договор от " + value + " регулируется законом.", [(value, "DATE", "privacy-filter")])
    assert next(f for f in fs if f.exact_text == value).status != "rejected"


def test_regulation_reference_is_not_a_bank_account():
    number = "2018/1725"
    _, fs = detected("Article 6 of Regulation (EU) " + number + ".",
                     [(number, "ACCOUNT", "privacy-filter")])
    assert next(f for f in fs if f.exact_text == number).status == "rejected"
    _, fs = detected("Account: " + number + ".", [(number, "ACCOUNT", "privacy-filter")])
    assert next(f for f in fs if f.exact_text == number).status != "rejected"
