import html
import json
import os
from pathlib import Path
from .evidence import canonical

COLORS={'red':('Красный','#b42318'),'yellow':('Жёлтый','#856400'),'grey':('Серый','#525866'),'green':('Зелёный','#067647')}
OUTCOMES={'pass':'Проверено','fail':'Замечание','not_applicable':'Неприменимо','not_checked':'Не проверено','inconclusive':'Недостаточно данных'}


def validate_report(data):
    if not isinstance(data,dict) or data.get('schema_version')!='1.0': raise ValueError('unsupported_report_schema')
    for k in ('checks','findings','limitations'):
        if not isinstance(data.get(k),list): raise ValueError('invalid_report_'+k)
    if data.get('color') not in COLORS or data.get('scan_status') not in ('complete','partial','cancelled'): raise ValueError('invalid_report_status')
    if data.get('legal_verdict') is not None: raise ValueError('unexpected_legal_verdict')
    for k in ('coverage','metrics','inventory','urls','config','evidence'):
        if not isinstance(data.get(k),dict): raise ValueError('invalid_report_'+k)
    for check in data['checks']:
        if check.get('outcome') not in OUTCOMES: raise ValueError('invalid_outcome')
    return data


def render_html(result):
    validate_report(result)
    esc=lambda x:html.escape(str(x),quote=True)
    color, css=COLORS[result['color']]
    cov=result['coverage']
    findings=''.join('<article><h3>'+esc(f['rule_id'])+' · '+esc(f['fact'])+'</h3><p>'+esc(f['url'])+'</p><p>'+esc(f['recommendation'])+'</p><small>'+esc(f['reference'])+'</small></article>' for f in result['findings'])
    rows=''.join('<tr><td>'+esc(c['rule_id'])+'</td><td>'+esc(c['url'])+'</td><td>'+esc(OUTCOMES[c['outcome']])+'</td><td>'+esc(c['reason_code'])+'</td></tr>' for c in result['checks'])
    inventory=esc(json.dumps(result['inventory'],ensure_ascii=False,indent=2))
    skipped=esc(json.dumps(result['urls']['skipped'],ensure_ascii=False,indent=2))
    return '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>PDScan — отчёт</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:1150px;margin:30px auto;padding:0 20px;color:#18212f}a{color:#175cd3}nav{display:flex;gap:20px;flex-wrap:wrap}h1{font-size:28px}h2{margin-top:36px}article{border:1px solid #d0d5dd;border-radius:8px;padding:16px;margin:14px 0}article h3{margin-top:0}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #ddd;text-align:left;padding:9px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:14px}.badge{padding:8px 14px;color:white;border-radius:8px;display:inline-block}small{color:#667085}footer{margin-top:35px;border-top:1px solid #ddd}</style><h1>PDScan · техническая проверка сайта</h1>'''+f'''<p>{esc(result.get('target'))}</p><p class="badge" style="background:{css}">{color}</p><p>Статус: {esc(result['scan_status'])}. Проверено объектов: {esc(cov.get('completed',0))} / {esc(cov.get('planned',0))}. Это не доля всего сайта.</p><p>Версия: {esc(result.get('scanner_version'))} · {esc(result.get('finished_at'))}</p><nav><a href="#findings">Замечания</a><a href="#checks">Проверки</a><a href="#inventory">Инвентаризация</a><a href="#limits">Ограничения</a></nav><h2 id="findings">Замечания</h2>{findings or '<p>Технических замечаний не зафиксировано в выполненных проверках. Это не подтверждение соответствия законодательству.</p>'}<h2 id="checks">Результаты проверок</h2><table><tr><th>Правило</th><th>Объект</th><th>Результат</th><th>Причина</th></tr>{rows}</table><h2 id="inventory">Инвентаризация</h2><pre>{inventory}</pre><h2 id="limits">Ограничения</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in result['limitations'])}</ul><h3>Пропущенные адреса</h3><pre>{skipped}</pre><footer><p>Автоматические технические наблюдения. Юридическое заключение и расчёт штрафов не выполнялись.</p></footer></html>'''


def prepare_output(path, overwrite=False):
    path=Path(path)
    if path.is_symlink(): raise ValueError('output_symlink')
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        if not overwrite: raise ValueError('output_exists_use_new_directory')
        # Overwrite only owned files of an existing PDScan report; never recursive delete.
        if not (path/'manifest.json').is_file(): raise ValueError('not_pdscan_output')
        for name in ('report.json','report.html','manifest.json','sanitized.log','evidence'):
            if (path/name).is_symlink(): raise ValueError('output_symlink')
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    return path


def write_file(path,content):
    path=Path(path)
    import tempfile
    if path.is_symlink(): raise ValueError('output_symlink')
    fd, temporary = tempfile.mkstemp(prefix='.pdscan-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f: f.write(content)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)



def render(result, output, overwrite=False):
    validate_report(result)
    path=prepare_output(output,overwrite)
    evdir=path/'evidence'
    if evdir.is_symlink(): raise ValueError('output_symlink')
    evdir.mkdir(exist_ok=True,mode=0o700)
    for sha,ev in result['evidence'].items():
        import re,hashlib
        if not re.fullmatch('[a-f0-9]{64}',sha) or hashlib.sha256(canonical(ev['data'])).hexdigest()!=sha:
            raise ValueError('invalid_evidence_hash')
        write_file(evdir/(sha+'.json'),canonical(ev))
    write_file(path/'report.json',json.dumps(result,ensure_ascii=False,indent=2).encode())
    write_file(path/'report.html',render_html(result).encode())
    manifest={k:result[k] for k in ('scan_id','schema_version','scanner_version','ruleset_version','config','started_at','finished_at','metrics')}
    manifest['files']=['report.json','report.html','sanitized.log']
    manifest['evidence_sha256']=list(result['evidence'])
    write_file(path/'manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2).encode())
    write_file(path/'sanitized.log',f"scan_status={result['scan_status']}\ncolor={result['color']}\nrequests={result['metrics']['requests']}\n".encode())
    return path
