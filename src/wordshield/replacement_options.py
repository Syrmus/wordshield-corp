"""Versioned per-upload category selection and human-readable placeholders."""
import re

CATEGORIES = (
    ('person', 'ФИО и инициалы', ('PERSON',)),
    ('company', 'Компании и организации', ('ORG',)),
    ('address', 'Адреса и города', ('ADDRESS','CITY')),
    ('email', 'Электронная почта', ('EMAIL',)),
    ('phone', 'Телефоны', ('PHONE',)),
    ('url', 'Ссылки и сайты', ('URL',)),
    ('passport', 'Паспортные номера', ('PASSPORT',)),
    ('personal_id', 'СНИЛС, SSN и личные идентификаторы', ('PERSONAL_ID',)),
    ('tax', 'ИНН, КПП и налоговые номера', ('TAX_ID',)),
    ('registration', 'ОГРН и регистрационные номера', ('REG_ID',)),
    ('bank', 'Банковские реквизиты: счета, карты, IBAN, SWIFT, БИК', ('BANK',)),
    ('document', 'Номера договоров, счетов, дел и заказов', ('DOCUMENT_ID',)),
    ('amount', 'Суммы, цены, проценты и условия оплаты', ('PRICE',)),
    ('date', 'Даты документа и персональные даты', ('DATE',)),
    ('time', 'Время', ('TIME',)),
    ('account', 'Логины и идентификаторы аккаунтов', ('ACCOUNT',)),
    ('secret', 'Пароли, ключи и токены', ('SECRET',)),
    ('ip', 'IP-адреса', ('IP',)),
    ('other', 'Прочие персональные данные', ('PII',)),
)
LABELS = {
    'PERSON': ('ФИО','Name'), 'ORG': ('компания','Company'),
    'ADDRESS': ('адрес','Address'), 'CITY': ('город','City'),
    'EMAIL': ('почта','Email'), 'PHONE': ('телефон','Phone'),
    'URL': ('ссылка','URL'), 'PASSPORT': ('паспорт','Passport'),
    'PERSONAL_ID': ('личный_номер','PersonalID'), 'TAX_ID': ('ИНН','TaxID'),
    'REG_ID': ('регномер','Registration'), 'BANK': ('реквизиты','Bank'),
    'DOCUMENT_ID': ('документ','Document'), 'PRICE': ('сумма','Amount'),
    'DATE': ('дата','Date'), 'TIME': ('время','Time'),
    'ACCOUNT': ('логин','Account'), 'SECRET': ('секрет','Secret'),
    'IP': ('IP','IP'), 'PII': ('данные','Data'),
}


def validate_options(value=None):
    value = {} if value is None else value
    if not isinstance(value,dict) or set(value)-{'categories','language','version'}:
        raise ValueError('Некорректные настройки обезличивания')
    if value.get('version',2) != 2:
        raise ValueError('Неизвестная версия плейсхолдеров')
    categories=value.get('categories',[key for key,_,_ in CATEGORIES])
    known={key for key,_,_ in CATEGORIES}
    if not isinstance(categories,list) or not categories or any(not isinstance(key,str) or key not in known for key in categories):
        raise ValueError('Выберите хотя бы один известный тип данных')
    language=value.get('language','ru')
    if language not in ('ru','en'):
        raise ValueError('Выберите русский или английский язык плейсхолдеров')
    return {'version':2,'categories':sorted(set(categories)),'language':language}


def selected_types(options):
    if options is None:
        return set(LABELS)
    options=validate_options(options)
    return {kind for key,_,types in CATEGORIES if key in options['categories'] for kind in types}


def selected_findings(findings, options):
    types=selected_types(options)
    return [f for f in findings if f.entity_type in types or
            (f.entity_type=='PII' and 'overlap-auto' in f.sources)]


def short_aliases(findings, options):
    """Dictionary labels/numbers stay stable; ordinary counters are per entity type."""
    language=validate_options(options)['language']
    aliases={}
    used=set()
    counters={}
    for f in findings:
        if f.alias and (match:=re.fullmatch(r'\[\[([A-Z_]+)-GLOB-(\d+)(?::([^\[\]\r\n]{1,80}))?\]\]',f.alias)):
            label=match[3] or LABELS[f.entity_type][language=='en']
            alias=f'[{label}_{int(match[2])}]'
            key=(f.entity_type,f.exact_text)
            if alias in used and aliases.get(key)!=alias:
                raise ValueError('Постоянные замены имеют совпадающие плейсхолдеры')
            aliases[key]=alias
            used.add(alias)
    for f in findings:
        key=(f.entity_type,f.exact_text)
        if key not in aliases:
            label=LABELS[f.entity_type][language=='en']
            number=counters.get(label,0)+1
            while f'[{label}_{number}]' in used:
                number+=1
            counters[label]=number
            aliases[key]=f'[{label}_{number}]'
            used.add(aliases[key])
        f.alias=aliases[key]
    return aliases
