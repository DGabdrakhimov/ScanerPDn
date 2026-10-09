from collections import deque
from dataclasses import asdict
import time
import uuid
from urllib.parse import urlsplit
from . import __version__, SCHEMA_VERSION, RULESET_VERSION
from .config import ScanError
from .evidence import now, safe_url, token, artifact
from .extractors import extract, cookies_inventory
from .rules import RULES, evaluate, REFERENCE
from .transport import Transport, Observation

LIMITATION = 'Поверхностная автоматическая проверка HTTP и статического HTML. JavaScript, внутренние процессы и правомерность обработки не оценивались.'


def evidence(obs, attempt, parsed=None):
    data = {'url': safe_url(obs.requested), 'final': safe_url(obs.final), 'at': obs.at, 'attempt': attempt,
            'status': obs.status, 'error': obs.error, 'tls_code': obs.tls_code,
            'chain': [{'url': safe_url(h.url), 'status': h.status} for h in obs.chain],
            'body_length': len(obs.body), 'content_type': obs.content_type if obs.content_type in ('text/html','application/xhtml+xml','application/pdf','text/plain') else 'other'}
    if parsed is not None:
        data['forms'] = clean_forms(parsed['forms'])
        data['ambiguous_html'] = parsed['ambiguous']
    return artifact(data)


def clean_forms(forms):
    return [{'index': f['index'], 'method': f['method'], 'fields': [{'type': x['type'] if x['type'] in ('email','tel','password','text','hidden','submit','checkbox','radio','textarea','select','button','image') else 'other', 'name': x['name']} for x in f['fields']],
             'action': safe_url(f['action']) if f['action'] else None,
             'formaction': [safe_url(u) for u in f['overrides'] if u]} for f in forms]


def scan(config, *, transport=None, progress=None):
    config.validate()
    start = time.monotonic()
    client = transport or Transport(config)
    result = {'schema_version': SCHEMA_VERSION, 'scanner_version': __version__, 'ruleset_version': RULESET_VERSION,
              'scan_id': str(uuid.uuid4()), 'started_at': now(), 'finished_at': None, 'target': safe_url(config.target),
              'scope': {'hosts': sorted(config.hosts), 'mode': 'http-static'}, 'config': config.public_dict(),
              'scan_status': 'complete', 'color': 'grey', 'checks': [], 'findings': [], 'inventory': {'documents': [], 'forms': [], 'cookies': [], 'external_hosts': []},
              'evidence': {}, 'coverage': {}, 'urls': {'known': [], 'visited': [], 'skipped': []},
              'limitations': [LIMITATION, 'URL с query-параметрами не запрашиваются: в GET возможны действия и секреты.', 'Кандидат в релиз: полевой пилот и проверка WSL2/контейнера должны быть завершены отдельно.'],
              'legal_verdict': None}
    pending = deque([(config.target, 0, False)])
    queued = {(config.target, False)}
    visited = set()
    known = {config.target}
    pages = 0
    skipped_raw = []
    document_targets = set()
    cancelled = False
    ext = set()
    def skip(url, reason):
        result['scan_status'] = 'partial'
        skipped_raw.append((url,reason))
        result['urls']['skipped'].append({'url': safe_url(url), 'reason': reason})
    def add_checks(url, doc, a, b, parsed=None):
        pa = parsed if parsed is not None else (extract(a) if a.content_type in ('text/html','application/xhtml+xml') and not doc else None)
        pb = extract(b) if b.content_type in ('text/html','application/xhtml+xml') and not doc else None
        refs = []
        for i, (ob, pp) in enumerate(((a,pa),(b,pb)),1):
            ev = evidence(ob,i,pp); ref = ev['sha256']; result['evidence'][ref] = ev; refs.append(ref)
        for rule in RULES:
            outcome, _, message, severity = evaluate(rule,a,b,doc,pa)
            check = {'rule_id': rule, 'machine_key': RULES[rule][0], 'url': safe_url(url), 'outcome': outcome,
                     'reason_code': outcome if outcome != 'inconclusive' else (a.error or b.error or 'inconsistent_or_unavailable'), 'evidence_refs': refs}
            result['checks'].append(check)
            if outcome == 'inconclusive': result['scan_status'] = 'partial'
            if outcome == 'fail':
                result['findings'].append({'finding_id': token(rule+url), 'rule_id':rule, 'url':safe_url(url), 'fact':message,
                                           'technical_severity':severity, 'color':'red' if severity=='high' else 'yellow',
                                           'recommendation':RULES[rule][2], 'reference':REFERENCE, 'legal_verdict':None, 'evidence_refs':refs})
    active = None
    try:
        while pending:
            url, depth, doc = pending.popleft()
            active = (url, doc)
            if not doc and pages >= config.max_pages:
                skip(url, 'page_limit'); continue
            if progress: progress(len(visited)+1, len(pending))
            a = client.fetch(url, document=doc)
            b = client.fetch(url, document=doc)
            visited.add(url)
            result['urls']['visited'].append(safe_url(url))
            if not doc: pages += 1
            parsed = extract(a) if not doc and not a.error and a.status==200 and a.content_type in ('text/html','application/xhtml+xml') else None
            add_checks(url,doc,a,b,parsed)
            active = None
            if a.error or b.error:
                skip(url, a.error or b.error)
            result['inventory']['cookies'].extend(cookies_inventory(a.cookies+b.cookies))
            if doc: continue
            if not parsed: continue
            result['inventory']['forms'].extend({'page':safe_url(url), **f} for f in clean_forms(parsed['forms']))
            for value in parsed['resources']+[u for f in parsed['forms'] for u in [f['action'],*f['overrides']] if u]:
                host=urlsplit(value).hostname
                if host not in config.hosts: ext.add(host)
            # Explicitly labeled documents are always queued first, with separate rule context.
            for link in sorted(parsed['links'], key=lambda x:not x['document']):
                u, isdoc = link['url'], link['document']
                host=urlsplit(u).hostname
                if host not in config.hosts: ext.add(host)
                if isdoc: document_targets.add(u)
                if isdoc or link['candidate']:
                    result['inventory']['documents'].append({'url':safe_url(u),'source':safe_url(url),'label':link['label'],'explicit':isdoc})
                if host not in config.hosts and not (isdoc and config.check_external_docs):
                    if isdoc: known.add(u); skip(u,'external_document_not_enabled')
                    continue
                known.add(u)
                if (u,isdoc) in queued: continue
                queued.add((u,isdoc))
                if not isdoc and depth >= config.max_depth:
                    skip(u,'depth_limit'); continue
                if len(queued)>2000:
                    skip(u,'queue_limit'); continue
                try: client.allowed(u,external=isdoc)
                except ScanError as exc:
                    skip(u,str(exc)); continue
                if isdoc: pending.appendleft((u,depth+1,True))
                else: pending.append((u,depth+1,False))
            if client.remaining() <= 0 or client.requests >= config.max_requests or client.bytes >= config.byte_limit:
                break
    except KeyboardInterrupt:
        cancelled = True
        result['scan_status']='cancelled'
        if active:
            url,doc=active
            unknown=Observation(url,url,error='cancelled')
            add_checks(url,doc,unknown,unknown)
            result['scan_status']='cancelled'
    if pending:
        for u,_,doc in pending:
            skip(u,'job_budget_exhausted')
    accounted = set(visited)
    for u, reason in skipped_raw:
        if u not in accounted:
            unknown = Observation(u,u,error=reason)
            add_checks(u,u in document_targets,unknown,unknown)
            accounted.add(u)
    if cancelled: result['scan_status']='cancelled'
    result['inventory']['external_hosts']=sorted(ext)
    for key in ('documents','cookies','forms'):
        # Insertion order retained; values already sanitized.
        import json
        result['inventory'][key]=list({json.dumps(v,sort_keys=True):v for v in result['inventory'][key]}.values())
    result['urls']['known']=sorted(safe_url(u) for u in known)
    applicable=[c for c in result['checks'] if c['outcome']!='not_applicable']
    completed=sum(c['outcome'] in ('pass','fail') for c in applicable)
    result['coverage']={'completed':completed,'planned':len(applicable),'ratio':completed/len(applicable) if applicable else None,
                        'known_urls':len(known),'visited_urls':len(visited),'skipped_urls':len(result['urls']['skipped']),
                        'note':'Покрытие обнаруженных объектов, не всего сайта.'}
    colors={f['color'] for f in result['findings']}
    result['color']='red' if 'red' in colors else 'yellow' if 'yellow' in colors else 'grey' if result['scan_status']!='complete' or not completed else 'green'
    result['finished_at']=now()
    result['metrics']={'requests':client.requests,'bytes':client.bytes,'elapsed_seconds':round(time.monotonic()-start,3)}
    return result
