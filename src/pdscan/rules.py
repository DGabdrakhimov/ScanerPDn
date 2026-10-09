from urllib.parse import urlsplit
from .extractors import extract

RULES = {
 'C01': ('protocol-page-v1', 'Протокол HTML-страницы', 'Проверьте доступность страницы по HTTPS и перенаправление с HTTP.'),
 'C02': ('tls-certificate-v1', 'Проверка сертификата TLS', 'Проверьте имя, срок, цепочку сертификата, часы и доверенные центры на машине сканера.'),
 'C03': ('document-status-v1', 'Недоступная ссылка на документ', 'Исправьте конкретную ссылку либо восстановите доступ к документу.'),
 'C04': ('document-loop-v1', 'Цикл перенаправлений документа', 'Устраните замкнутый цикл перенаправлений.'),
 'C05': ('document-downgrade-v1', 'Переход документа на HTTP', 'Проверьте HTTPS на всех переходах к документу.'),
 'C06': ('form-action-v1', 'HTTP-адрес формы в HTML', 'Проверьте action/formaction и фактическую обработку формы; используйте HTTPS.'),
 'C07': ('document-empty-v1', 'Пустой ответ документа', 'Проверьте выдачу документа по указанному адресу.')}
REFERENCE = 'Справочно: 152-ФЗ, статьи 18.1 и 19. Юридическая квалификация не выполняется.'


def single(rule, obs, document, parsed=None):
    """outcome, signature, message, severity. Signatures are memory-only, not exported."""
    na = ('not_applicable', (), 'Нет объекта для этого правила в обследованном ответе.', '')
    unknown = ('inconclusive', (), 'Недостаточно данных: ' + (obs.error or 'http_status_or_type'), '')
    ok = ('pass', (), 'Техническое условие проверено; дефект не обнаружен.', '')
    if rule in ('C03', 'C04', 'C05', 'C07') and not document: return na
    if rule in ('C01', 'C06') and document: return na
    if rule == 'C02':
        if obs.error == 'tls_certificate':
            return ('fail', (obs.final, obs.tls_code), 'В HTTP-проверке повторяется ошибка валидации сертификата TLS.', 'high')
        if obs.error: return unknown
        if any(urlsplit(h.url).scheme == 'https' for h in obs.chain) or urlsplit(obs.final).scheme == 'https': return ok
        return na
    if rule == 'C04' and obs.error == 'redirect_loop':
        return ('fail', tuple((h.url, h.status) for h in obs.chain)+(obs.final,), 'В HTTP-проверке ссылки на документ повторяется замкнутый цикл перенаправлений.', 'medium')
    if obs.error: return unknown
    if obs.status in (401, 403, 429) or obs.status >= 500 or not obs.status: return unknown
    if rule == 'C03':
        if obs.status in (404, 410):
            return ('fail', (obs.final, obs.status), 'В HTTP-проверке конкретная ссылка на документ возвращает '+str(obs.status)+'.', 'medium')
        return ok if obs.status == 200 else unknown
    if rule == 'C04': return ok
    if rule == 'C05':
        urls = [h.url for h in obs.chain] or [obs.final]
        down = tuple((a, b) for a, b in zip(urls, urls[1:]) if urlsplit(a).scheme == 'https' and urlsplit(b).scheme == 'http')
        if down: return ('fail', down, 'В HTTP-проверке ссылки на документ обнаружен переход с HTTPS на HTTP.', 'medium')
        return ok
    if rule == 'C07':
        if obs.status != 200: return unknown
        if obs.content_type not in ('text/html','application/xhtml+xml','text/plain','application/pdf'): return unknown
        if len(obs.body) == 0:
            return ('fail', (obs.final, 0), 'В HTTP-проверке ссылка на документ возвращает 200 с пустым телом ответа.', 'medium')
        return ok
    if obs.status != 200 or obs.content_type not in ('text/html', 'application/xhtml+xml'): return unknown
    parsed = parsed if parsed is not None else extract(obs)
    if parsed['ambiguous']: return ('inconclusive', (), 'Неоднозначная структура статического HTML.', '')
    if rule == 'C01':
        if urlsplit(obs.final).scheme == 'http':
            typed = any(f['typed'] for f in parsed['forms'])
            return ('fail', (obs.final, typed), 'HTML страницы'+(' с формой email/tel/password' if typed else '')+' получен без HTTPS.', 'high' if typed else 'medium')
        return ok
    if rule == 'C06':
        forms = [f for f in parsed['forms'] if f['typed'] and f['method'] != 'dialog']
        if not forms: return na
        targets = tuple(sorted({u for f in forms for u in [f['action'], *f['overrides']] if u and urlsplit(u).scheme == 'http'}))
        if targets: return ('fail', targets, 'В полученном статическом HTML задан HTTP-адрес отправки формы; форма не отправлялась.', 'medium')
        return ok
    return na


def evaluate(rule, first, second, document=False, parsed=None):
    a = single(rule, first, document, parsed)
    b = single(rule, second, document)
    if a[0] == b[0] == 'not_applicable': return a
    if a[0] == b[0] == 'fail' and a[1] == b[1] and a[3] == b[3]: return a
    if a[0] == b[0] == 'pass': return a
    return ('inconclusive', (), 'Две попытки не дали согласованного результата: '+(first.error or second.error or 'different_or_unavailable_observations'), '')
