"""Versioned legal context. R1 never derives a legal verdict from HTTP outcomes."""
from copy import deepcopy
from . import RULESET_VERSION

CHECKED_AT = '2026-10-14'
INVENTORY_NOTE = 'Информационные сведения; выполнение нормы не оценивалось.'
STATUS_LABELS = {'insufficient_data': 'Недостаточно данных', 'not_checked': 'Не проверено'}
BASE = 'https://www.consultant.ru/document/'


def norm(article, part, chapter, edition, effective, path, kind, summary, effective_source):
    return dict(norm_id=f'152-fz-art-{article}-part-{part}', act_type='Федеральный закон',
                act_title='О персональных данных', issuing_authority=None,
                act_number='152-ФЗ', act_date='2006-07-27', article=article, part=part,
                chapter=chapter, point=None, subpoint=None, section=None, annex=None, measure_code=None,
                obligation_summary=summary, reference_kind=kind, source_url=BASE+path,
                edition_date=edition, effective_from=effective, checked_at=CHECKED_AT,
                effective_source_url=BASE+effective_source)


NORMS = {
 'policy': norm('18.1','2','4','2022-07-14','2022-09-01',
  'cons_doc_LAW_61801/eeeebe22bf738fd65bb66b95cc278911ae2525ee/', 'direct_requirement',
  'Обеспечить доступ к политике и сведениям о реализуемой защите; при сборе через сеть опубликовать их в этой сети, включая страницы сбора.',
  'cons_doc_LAW_421898/46b4b351a6eb6bf3c553d41eb663011c2cb38810/'),
 'consent': norm('9','1','2','2025-06-24','2025-09-01',
  'cons_doc_LAW_61801/6c94959bc017ac80140621762d2ac59f6006b08c/', 'general_context',
  'При использовании согласия оно должно выражать свободное, конкретное, предметное, информированное, сознательное и однозначное волеизъявление и оформляться отдельно от иных подтверждаемых документов.',
  'cons_doc_LAW_508287/be44309fac236577892f06a9350937633563ef3c/'),
 'security': norm('19','1','4','2011-07-25','2011-07-27',
  'cons_doc_LAW_61801/ca9e5658710519f09ab2fdb8196fcb3eb024a051/', 'general_context',
  'Принимать необходимые правовые, организационные и технические меры защиты персональных данных. Норма не задаёт универсального требования HTTPS к каждой странице.',
  'cons_doc_LAW_117437/30b3f8c55f65557c253227a65b908cc075ce114a/')
}


def reference_text(basis):
    if not basis:
        return 'Прямая нормативная привязка не установлена'
    return '; '.join((f'гл. {n["chapter"]}, ' if n.get('chapter') else '')+(f'п. {n["point"]} ' if n.get('point') else '')+f'ч. {n["part"]} ст. {n["article"]} Федерального закона от {n["act_date"]} № {n["act_number"]} «{n["act_title"]}»' for n in basis)


def legal_fields(rule, outcome, document_type='unknown'):
    key = 'security' if rule in ('C01','C02','C05','C06') else document_type if rule in ('C03','C04','C07') else None
    basis = [deepcopy(NORMS[key])] if key in NORMS else []
    if key == 'policy':
        condition = 'Оператор и сбор ПДн через обследуемый сайт должны быть установлены; тип документа определён только по подписи ссылки.'
        reason = 'Доступность одной ссылки не доказывает содержание политики и полноту доступа на всех страницах сбора.'
        missing = ['Применимость обязанности к оператору и процессу', 'Содержание документа и иные способы доступа']
    elif key == 'consent':
        condition = 'Согласие используется как правовое основание обработки; это не установлено внешним HTTP-сканером.'
        reason = 'Нет универсальной обязанности публиковать отдельный файл согласия. HTTP-ответ не доказывает получение, содержание и отдельность согласия.'
        missing = ['Правовое основание обработки', 'Текст, действие пользователя и доказательства получения согласия']
    elif key == 'security':
        condition = 'Обработка ПДн и необходимые для неё меры защиты должны быть установлены.'
        reason = 'Наблюдение относится к техническому риску; обязательные меры и выполнение ч. 1 ст. 19 в целом не установлены.'
        missing = ['Обработка ПДн, угрозы и применимый состав мер', 'Реализация внутренних мер защиты']
    else:
        condition = 'Тип документа и применимая обязанность не установлены.'
        reason = 'Нет однозначно определённого документа для выбора нормы о политике или согласии; URL не используется для угадывания типа.'
        missing = ['Однозначный тип документа', 'Применимость конкретной обязанности']
    if outcome == 'not_applicable':
        reason += ' Техническое отсутствие объекта не подтверждает юридическую неприменимость нормы.'
    if outcome == 'not_checked':
        reason = 'Проверка не выполнена. ' + reason
    elif outcome == 'inconclusive':
        reason = 'Наблюдения неполны или противоречивы. ' + reason
    return dict(legal_basis=basis, legal_status='not_checked' if outcome == 'not_checked' else 'insufficient_data',
                legal_reason=reason, applicability={'status':'unknown','condition':condition},
                missing_evidence=missing, reference=reference_text(basis), legal_verdict=None)


def annotate(result, contexts):
    """Resolve after crawl: a later conflicting label must not leave an earlier guess."""
    for item in result['checks']:
        ctx = contexts.get(item['url'], []) if item['object_kind']=='document' else []
        types = {c['document_type'] for c in ctx}
        doc_type = next(iter(types)) if len(types)==1 else 'unknown'
        item['document_type'] = doc_type
        item['document_context'] = deepcopy(ctx)
        item.update(legal_fields(item['rule_id'],item['outcome'],doc_type))
    checks = {(x['rule_id'],x['url'],x['object_kind']):x for x in result['checks']}
    fields = ('legal_basis','legal_status','legal_reason','applicability','missing_evidence','reference','legal_verdict','document_type','document_context')
    for item in result['findings']:
        check = checks[(item['rule_id'],item['url'],item['object_kind'])]
        item.update({k:deepcopy(check[k]) for k in fields})
    result['legal_catalog'] = {'version':RULESET_VERSION,'checked_at':CHECKED_AT,
        'edition_date_semantics':'Дата редакции конкретной нормы, не всего закона.',
        'norms':deepcopy(list(NORMS.values()))}
    result['inventory_note'] = INVENTORY_NOTE
    return result

# R2 profiles are a contextual mapping, never an automatic legal verdict.
def browser_fields(rule,outcome):
    from copy import deepcopy
    basis=[deepcopy(NORMS['policy' if rule=='B01' else 'consent'])]
    if rule=='B05':
        basis=[norm('15','1','3','2006-07-27','2007-01-26','cons_doc_LAW_61801/5656527e0713bf229a6932ac7084dec50d0ebe1f/','general_context','Для прямого продвижения с использованием ПДн требуется предварительное согласие.','cons_doc_LAW_61801/ef9bf520d21be486bc22c54d1ebfe307039bad09/')]
        extra=deepcopy(basis[0]);extra.update(norm_id='152-fz-art-15-part-2',part='2',obligation_summary='Прекратить указанную обработку по требованию субъекта.');basis.append(extra)
        ad=deepcopy(basis[0]);ad.update(norm_id='38-fz-art-18-part-1',act_title='О рекламе',act_number='38-ФЗ',act_date='2006-03-13',article='18',part='1',chapter='2',edition_date='2006-03-13',effective_from='2006-07-01',source_url=BASE+'cons_doc_LAW_58968/f892dec1383709792452f18d36e7043306e2be0a/',effective_source_url=BASE+'cons_doc_LAW_58968/7aea2ae9b1d27e88114ff4330d7c5321d9be3dc6/',obligation_summary='Предварительное согласие адресата на рекламу по сетям электросвязи; прекращение по требованию.');basis.append(ad)
    if rule=='B06':
        extra=deepcopy(NORMS['consent']);extra.update(norm_id='152-fz-art-9-part-2',part='2',edition_date='2011-07-25',effective_from='2011-07-27',effective_source_url=NORMS['security']['effective_source_url'],obligation_summary='Возможен отзыв согласия; обработка может продолжаться по иным предусмотренным основаниям.');basis.append(extra)
        base=deepcopy(NORMS['security']);base.update(norm_id='152-fz-art-6-part-1-point-1',article='6',part='1',point='1',chapter='2',source_url=BASE+'cons_doc_LAW_61801/315f051396c88f1e4f827ba3f2ae313d999a1873/',obligation_summary='Согласие является одним из оснований обработки персональных данных.');basis.append(base)
    return {'legal_basis':basis,'legal_status':'not_checked' if outcome=='not_checked' else 'insufficient_data','legal_reason':'Сохранён только ограниченный факт интерфейса или запросов. Правовое основание, содержание документов и действительность согласия не установлены.','applicability':{'status':'unknown','condition':'Необходимо установить оператора, обработку ПДн, цель и используемое правовое основание.'},'missing_evidence':['Содержание документов и правовое основание','Реальная обработка и доказательство волеизъявления'], 'reference':reference_text(basis),'legal_verdict':None}
