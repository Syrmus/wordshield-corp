"""Exact known OOXML schema identifiers, never a domain-wide URL exemption."""
SCHEMA_URIS = frozenset({
    'http://schemas.openxmlformats.org/officeDocument/2006/bibliography',
    'http://schemas.openxmlformats.org/officeDocument/2006/customXml',
    'http://schemas.openxmlformats.org/officeDocument/2006/customXmlDataProps',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
    'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties',
    'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes',
    'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'http://schemas.openxmlformats.org/package/2006/relationships',
    'http://schemas.openxmlformats.org/package/2006/content-types',
    'http://schemas.microsoft.com/office/word/2006/wordml',
    'http://www.w3.org/2001/XMLSchema',
    'http://www.w3.org/2001/XMLSchema-instance',
    'http://www.w3.org/XML/1998/namespace',
    'http://purl.org/dc/elements/1.1/',
    'http://purl.org/dc/terms/',
})


def technical_schema_block(block):
    return (block.kind.startswith('custom-xml-')
            and block.text.strip() in SCHEMA_URIS)


def omit_technical_schemas(blocks, findings):
    ignored = {b.id for b in blocks if technical_schema_block(b)}
    return [f for f in findings if f.block_id not in ignored]
