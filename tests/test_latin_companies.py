import pytest
from wordshield.detectors import LATIN_COMPANY_RE, RulesDetector, merge_detections
from wordshield.models import Block


@pytest.mark.parametrize('name',[
    'Example Trading Ltd','Example Trading LIMITED','Example GmbH',
    "I'10 Limited",'I’10 Ltd.','Example, Inc.','Example L.L.C.',
    'Example Pte. Ltd.','Example Pty Ltd','Example GmbH & Co. KG',
    'Example B.V.','Example S.A.R.L.','Example Corporation',
    'Example LLP','Example AG','Example UG (haftungsbeschränkt)',
    'House of Example Limited','eBay Ltd','«example trading» Limited',
])
def test_complete_company_with_legal_form(name):
    text='Сторона договора: '+name+'; адрес указан ниже.'
    b=Block('b','word/document.xml','paragraph',text)
    found=RulesDetector().detect([b])
    assert any(d.entity_type=='ORG' and d.exact_text==name for d in found)
    merged=merge_detections([b],found)
    assert any(f.entity_type=='ORG' and f.exact_text==name and f.status=='accepted' for f in merged)


@pytest.mark.parametrize('text',[
    'Resources are limited','This is a limited offer','LLC is a legal form',
    'The liability is limited to 100','Unrelated heading\nExample Ltd',
])
def test_no_sentence_or_heading_swallowing(text):
    matches=[m.group() for m in LATIN_COMPANY_RE.finditer(text)]
    assert matches==(['Example Ltd'] if '\n' in text else [])


def test_english_field_label_is_not_part_of_name():
    assert LATIN_COMPANY_RE.search('Supplier Example Trading Limited').group()=='Example Trading Limited'
