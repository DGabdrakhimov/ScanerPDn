"""Static HTML only. No raw values or page text leave extraction."""
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit
import re
from .config import normalize_url, ScanError
from .evidence import safe_url, safe_name, token

LABELS = ('политика обработки персональных данных', 'политика в отношении обработки персональных данных',
          'политика конфиденциальности', 'согласие на обработку персональных данных')
TYPED = {'email', 'tel', 'password'}


def label_match(text):
    text = ' '.join(text.lower().split()).strip(' .,;:«»"\'')
    return next((x for x in LABELS if text == x), None)


class Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.controls, self.resources = [], [], [], []
        self.anchor = None
        self.form = None
        self.base = None
        self.suppressed = 0
        self.ambiguous = False
        self.elements = 0

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        if self.elements > 20000: raise ScanError('html_element_limit')
        if tag == 'template': self.suppressed += 1
        if self.suppressed: return
        a = dict(attrs)
        if len(a) != len(attrs): self.ambiguous = True
        if tag == 'base' and self.base is None and a.get('href'): self.base = a['href']
        if tag == 'form':
            if self.form is not None: self.ambiguous = True
            self.form = len(self.forms)
            self.forms.append({'id': a.get('id'), 'action': a.get('action'), 'method': (a.get('method') or 'get').lower(), 'fields': [], 'overrides': []})
        if tag in ('input', 'textarea', 'select', 'button'):
            # An explicit form=id overrides lexical nesting, including for outside controls.
            self.controls.append({'owner': a.get('form'), 'nested': self.form, 'type': (a.get('type') or ('text' if tag == 'input' else 'submit' if tag == 'button' else tag)).lower(),
                                  'name': a.get('name'), 'action': a.get('formaction'), 'tag': tag})
        if tag == 'a' and a.get('href'):
            self.anchor = {'href': a['href'], 'text': '', 'label': a.get('aria-label') or a.get('title') or ''}
        for attr in ('src', 'href' if tag in ('link',) else 'src-placeholder'):
            if a.get(attr): self.resources.append(a[attr])

    def handle_endtag(self, tag):
        if tag == 'template' and self.suppressed: self.suppressed -= 1; return
        if self.suppressed: return
        if tag == 'form': self.form = None
        if tag == 'a' and self.anchor:
            self.links.append(self.anchor)
            self.anchor = None

    def handle_data(self, data):
        if self.anchor and not self.suppressed: self.anchor['text'] += data[:4096]


def extract(obs):
    p = Parser()
    try:
        try: html = obs.body.decode(obs.charset, errors='replace')
        except LookupError: html = obs.body.decode('utf-8', errors='replace')
        p.feed(html)
        p.close()
    except (ScanError, ValueError, RecursionError):
        return {'links': [], 'forms': [], 'resources': [], 'ambiguous': True, 'error': 'html_parse_limit'}
    if p.anchor: p.links.append(p.anchor)
    def absolute(value, base):
        try: return normalize_url(urljoin(base, value))
        except (ScanError, ValueError): return None
    base = absolute(p.base, obs.final) if p.base else obs.final
    if not base: p.ambiguous = True; base = obs.final
    ids = {}
    for i, f in enumerate(p.forms):
        if f['id']:
            if f['id'] in ids: p.ambiguous = True
            ids[f['id']] = i
    for c in p.controls:
        i = ids.get(c['owner']) if c['owner'] is not None else c['nested']
        if i is not None:
            p.forms[i]['fields'].append({'type': c['type'], 'name': safe_name(c['name']) if c['name'] else None})
            if c['action'] and (c['tag'] == 'button' and c['type'] == 'submit' or c['tag'] == 'input' and c['type'] in ('submit', 'image')):
                    p.forms[i]['overrides'].append(absolute(c['action'], base))
    if any(f['action'] and not absolute(f['action'], base) for f in p.forms): p.ambiguous = True
    if any(None in f['overrides'] for f in p.forms): p.ambiguous = True
    forms = []
    for i, f in enumerate(p.forms):
        forms.append({'index': i, 'fields': f['fields'], 'method': f['method'] if f['method'] in ('get', 'post', 'dialog') else 'unknown',
                      'typed': any(x['type'] in TYPED for x in f['fields']),
                      'action': absolute(f['action'], base) if f['action'] else None, 'overrides': f['overrides']})
    links = []
    for a in p.links:
        url = absolute(a['href'], base)
        if not url: continue
        label = label_match(a['text']) or label_match(a['label'])
        links.append({'url': url, 'document': bool(label), 'label': label,
                      'candidate': not label and bool(re.search(r'privacy|policy|consent', a['href'], re.I))})
    resources = [u for u in (absolute(x, base) for x in p.resources) if u]
    return {'forms': forms, 'links': links, 'resources': resources, 'ambiguous': p.ambiguous, 'error': ''}


def cookies_inventory(pairs):
    out = []
    for url, raw in pairs:
        cookie = SimpleCookie()
        try: cookie.load(raw)
        except CookieError: continue
        for name, m in cookie.items():
            try: expiry = parsedate_to_datetime(m['expires']).isoformat() if m['expires'] else None
            except (ValueError, TypeError, OverflowError): expiry = None
            out.append({'source': safe_url(url), 'name': safe_name(name),
                        'domain': token(m['domain']) if m['domain'] else None,
                        'path': token(m['path']) if m['path'] else None,
                        'expires_present': bool(m['expires']), 'expires': expiry,
                        'max_age': int(m['max-age']) if re.fullmatch(r'-?[0-9]{1,10}', m['max-age']) else None,
                        'secure': bool(m['secure']), 'httponly': bool(m['httponly']),
                        'samesite': m['samesite'].lower() if m['samesite'].lower() in ('lax','strict','none') else 'unspecified'})
    return out
