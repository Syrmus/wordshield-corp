import pytest
from wordshield.models import Block, Detection
from wordshield.technical_metadata import technical_schema_block
from wordshield.detectors import merge_detections

URI='http://schemas.openxmlformats.org/officeDocument/2006/bibliography'

def test_known_schema_not_a_finding_even_when_models_agree():
    b=Block('b','customXml/itemProps1.xml','custom-xml-attribute:uri',URI)
    ds=[Detection(b.id,0,len(URI),URI,'URL',s,.99,True) for s in ('rules','custom-xml','privacy-filter')]
    assert technical_schema_block(b)
    assert merge_detections([b],ds)==[]

@pytest.mark.parametrize('value',[URI+'?email=user@example.org',URI+'/private',
    URI+'#account',URI.replace('schemas.openxmlformats.org','schemas.openxmlformats.org.evil.example'),
    'https://internal.example/schema',URI+' user@example.org'])
def test_no_domain_or_prefix_exemption(value):
    assert not technical_schema_block(Block('b','customXml/item1.xml','custom-xml-attribute:uri',value))

def test_normal_document_links_not_excluded():
    assert not technical_schema_block(Block('b','word/document.xml','paragraph',URI))
