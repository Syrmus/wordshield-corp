from wordshield.models import Block
from wordshield.detectors import RulesDetector, merge_detections


def findings(text):
    block = Block("test", "word/document.xml", "paragraph", text)
    return merge_detections([block], RulesDetector().detect([block]))


def test_comma_separated_passport_does_not_hide_issuer_from_scanner():
    text = "Паспорт: 45 16 123456, выдан ГУ МВД России по Нижегородской области 14.03.2022, код подразделения 520-001."
    fs = findings(text)
    assert any(f.exact_text == "ГУ МВД России по Нижегородской области" and f.status == "accepted" for f in fs)
    assert any(f.exact_text == "520-001" and f.entity_type == "DOCUMENT_ID" for f in fs)


def test_address_stops_at_next_sentence_not_street_abbreviations():
    address = "603000, г. Нижний Новгород, ул. Большая Покровская, д. 17, корп. 2, кв. 41"
    fs = findings("Адрес регистрации: " + address + ". Для уведомлений: alena.test+contract@example.org.")
    assert any(f.exact_text == address and f.status == "accepted" for f in fs)
    assert any(f.exact_text == "alena.test+contract@example.org" and f.status == "accepted" for f in fs)
    assert not any("Для уведомлений" in f.exact_text for f in fs)


def test_money_unicode_spacing_and_written_payment_terms():
    for space in (" ", "\u00a0", "\u202f"):
        value = f"1{space}250{space}000,50 ₽"
        fs = findings(f"Стоимость услуг составляет {value}; аванс 30 процентов, остаток уплачивается в течение 7 рабочих дней после приёмки.")
        for expected in (value, "30 процентов", "в течение 7 рабочих дней после приёмки"):
            assert any(f.exact_text == expected and f.entity_type == "PRICE" for f in fs)


def test_full_company_name_and_neutral_terms():
    org = "Общество с ограниченной ответственностью «Учебный север»"
    assert any(f.exact_text == org for f in findings("Заказчик — " + org + "."))
    fs = findings("Работа завершена в течение 7 рабочих дней после приёмки. Документ содержит 30 процентов примеров.")
    assert not any(f.entity_type == "PRICE" for f in fs)
