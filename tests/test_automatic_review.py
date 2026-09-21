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


def test_rules_keep_values_on_opposite_sides_of_word_break_separate():
    text = "Emily Rose CarterNorthbridge Analytics Ltd"
    boundary = len("Emily Rose Carter")
    block = Block("b", "word/document.xml", "paragraph", text,
                  [f"hard-boundary:{boundary}"])
    detections = RulesDetector().detect([block])
    assert any(d.exact_text == "Northbridge Analytics Ltd" and d.entity_type == "ORG"
               for d in detections)
    assert not any(d.start < boundary < d.end for d in detections)
    crossed = Detection("b", 0, len(text), text, "PERSON", "privacy-filter", .9)
    assert not merge_detections([block], detections + [crossed]) == []
    assert not any(f.start < boundary < f.end
                   for f in merge_detections([block], detections + [crossed]))


def test_complete_email_beats_partial_person_span():
    value = "test.owner@aurora-example.test"
    block, findings = detected(value, [("@aurora-example.test", "PERSON", "privacy-filter")])
    assert any(f.exact_text == value and f.entity_type == "EMAIL" and f.status == "accepted"
               for f in findings)
    assert not any(f.exact_text == "@aurora-example.test" for f in findings)


def test_english_ids_address_and_commercial_terms_are_format_confirmed():
    text = (
        "company number 11820473; Invoice INV-2026-09-8841; "
        "18 Willow Quay, Bristol BS1 4RT, United Kingdom; "
        "VAT 20%; 40% advance; 2.25% service fee; payment within 12 business days"
    )
    block = Block("b", "word/document.xml", "paragraph", text)
    findings = merge_detections([block], RulesDetector().detect([block]))
    accepted = {(f.exact_text, f.entity_type) for f in findings if f.status == "accepted"}
    assert ("11820473", "DOCUMENT_ID") in accepted
    assert ("INV-2026-09-8841", "DOCUMENT_ID") in accepted
    assert ("18 Willow Quay, Bristol BS1 4RT, United Kingdom", "ADDRESS") in accepted
    for value in ("20%", "40%", "2.25%", "payment within 12 business days"):
        assert (value, "PRICE") in accepted


def test_neutral_references_and_schema_urls_are_silently_skipped():
    schema = "http://schemas.openxmlformats.org/officeDocument/2006/bibliography"
    text = schema + "; ISO 27001, Article 6 of Regulation (EU) 2016/679; page 2, section 4.2"
    block = Block("b", "word/document.xml", "paragraph", text)
    detections = RulesDetector().detect([block])
    for value in ("ISO 27001, Article 6 of Regulation (EU) 2016/679", "page 2, section 4.2"):
        start = text.index(value)
        detections.append(Detection("b", start, start + len(value), value,
                                    "ADDRESS", "privacy-filter", .9))
    findings = merge_detections([block], detections)
    assert not any(f.exact_text == schema for f in findings)
    assert not any(f.entity_type == "ADDRESS" for f in findings)


def test_header_time_login_password_and_public_date_need_no_review():
    text = (
        "Санкт-Петербург, 21 сентября 2026 года, 14:35. "
        "Login: emily.carter. password Winter-Signal-883!. "
        "public date 27 April 2016."
    )
    block = Block("b", "word/document.xml", "paragraph", text)
    detections = RulesDetector().detect([block])
    public_date = "27 April 2016"
    start = text.index(public_date)
    detections.append(Detection("b", start, start + len(public_date), public_date,
                                "DATE", "privacy-filter", .9))
    findings = merge_detections([block], detections)
    assert any(f.exact_text == "14:35" and f.status == "accepted" for f in findings)
    assert any(f.exact_text == "emily.carter" and f.entity_type == "ACCOUNT"
               and f.status == "accepted" for f in findings)
    assert any(f.exact_text == "Winter-Signal-883!" and f.entity_type == "SECRET"
               and f.status == "accepted" for f in findings)
    assert any(f.exact_text == public_date and f.status == "rejected" for f in findings)


def test_specific_format_in_custom_xml_is_accepted():
    text = "Northbridge Analytics Ltd"
    block = Block("b", "customXml/item1.xml", "custom-xml-text", text)
    detections = RulesDetector().detect([block])
    findings = merge_detections([block], detections)
    assert any(f.exact_text == text and f.entity_type == "ORG" and f.status == "accepted"
               for f in findings)
