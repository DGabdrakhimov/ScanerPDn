import html
import json
import os
from pathlib import Path
from .evidence import canonical

COLORS={'red':('Красный','#b42318'),'yellow':('Жёлтый','#856400'),'grey':('Серый','#525866'),'green':('Зелёный','#067647')}
OUTCOMES={'pass':'Проверено','fail':'Замечание','not_applicable':'Неприменимо','not_checked':'Не проверено','inconclusive':'Недостаточно данных'}


def validate_report(data):
    if not isinstance(data,dict) or data.get('schema_version') not in ('1.0','1.1'): raise ValueError('unsupported_report_schema')
    for k in ('checks','findings','limitations'):
        if not isinstance(data.get(k),list): raise ValueError('invalid_report_'+k)
    if data.get('color') not in COLORS or data.get('scan_status') not in ('complete','partial','cancelled'): raise ValueError('invalid_report_status')
    if data.get('legal_verdict') is not None: raise ValueError('unexpected_legal_verdict')
    for k in ('coverage','metrics','inventory','urls','config','evidence'):
        if not isinstance(data.get(k),dict): raise ValueError('invalid_report_'+k)
    for check in data['checks']:
        if check.get('outcome') not in OUTCOMES: raise ValueError('invalid_outcome')
    if data['schema_version']=='1.1':
        for item in data['checks']+data['findings']:
            if not isinstance(item.get('legal_basis'),list) or item.get('legal_status') not in ('insufficient_data','not_checked') or not isinstance(item.get('missing_evidence'),list) or not isinstance(item.get('applicability'),dict) or not isinstance(item.get('legal_reason'),str): raise ValueError('invalid_legal_block')
            if item.get('legal_verdict') is not None: raise ValueError('unexpected_legal_verdict')
    return data


def render_html(result):
    from collections import Counter
    from . import __version__
    from .presentation import esc, table, explain, inventory_html, RULE_HELP, OUTCOMES, reason_text
    from .browser_presentation import legal_html, browser_html
    from .browser_rules import BROWSER_RULES
    from .browser_diagnostics import legal_matrix_html
    RULE_HELP={**RULE_HELP, **{k:(v[1],v[2],"Правовая квалификация не выполняется.") for k,v in BROWSER_RULES.items()}}
    validate_report(result)
    color, css=COLORS[result['color']]
    cov=result['coverage']
    def rule_name(rule): return RULE_HELP.get(rule,('Неизвестное правило',))[0]
    def rule_link(rule):
        label=esc(rule)+' · '+esc(rule_name(rule))
        return '<a href="#rule-'+esc(rule)+'">'+label+'</a>' if rule in RULE_HELP else label
    findings=''.join('<article><h3>'+rule_link(f['rule_id'])+'</h3><p>'+esc(f['fact'])+'</p><p><b>Адрес:</b> '+esc(f['url'])+'</p><p><b>Что проверить:</b> '+esc(f['recommendation'])+'</p><small>'+esc(f['reference'])+'</small>'+legal_html(f)+'</article>' for f in result['findings'])
    counts=Counter(c['outcome'] for c in result['checks'])
    summary=table(['Результат отдельной проверки','Количество'],[[esc(OUTCOMES[k]),v] for k,v in counts.items()])
    checks=table(['Правило','Объект','Результат','Объяснение результата'],[[rule_link(c['rule_id']),esc(c['url']),esc(OUTCOMES[c['outcome']]),esc(explain(c,result))+legal_html(c)+'<details><summary>Технический код</summary>'+esc(c.get('reason_code',''))+'</details>'] for c in result['checks']])
    incomplete=[c for c in result['checks'] if c['outcome'] in ('inconclusive','not_checked')]
    reasons=Counter(explain(c,result) for c in incomplete)
    partial='<h3>Почему проверка неполная</h3>'+table(['Объяснение','Количество проверок'],[[esc(k),v] for k,v in reasons.items()]) if reasons else ''
    skips=result['urls'].get('skipped',[])
    skipped=table(['Адрес','Почему пропущен'],[[esc(x.get('url','')),esc(reason_text(x.get('reason')))] for x in skips]) if skips else '<p>Пропущенных адресов в отчёте нет. При этом отдельные правила могли остаться без определённого результата.</p>'
    glossary=''.join('<article id="rule-'+k+'"><h3>'+k+' · '+esc(v[0])+'</h3><p>'+esc(v[1])+'</p><p><b>Границы проверки:</b> '+esc(v[2])+'</p></article>' for k,v in RULE_HELP.items())
    status={'complete':'Завершена в заданных пределах','partial':'Завершена частично','cancelled':'Остановлена пользователем'}[result['scan_status']]
    return '''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>PDScan — отчёт о проверке сайта</title><style>
body{font:16px/1.55 system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#18212f;background:#fff}a{color:#175cd3}nav{display:flex;gap:18px;flex-wrap:wrap;padding:18px 0;border-block:1px solid #ddd}h1{font-size:30px;line-height:1.2}h2{margin-top:36px}h3{font-size:19px}article{border:1px solid #d0d5dd;border-radius:8px;padding:18px;margin:14px 0}article h3{margin-top:0}.table-wrap{overflow-x:auto;margin:16px 0}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #ddd;text-align:left;padding:10px;overflow-wrap:anywhere;vertical-align:top}th{background:#eef2f6}tbody tr:nth-child(even){background:#fafbfd}.badge{padding:8px 14px;color:white;border-radius:8px;display:inline-block}small,details{color:#525866}details{margin-top:8px}footer{margin-top:35px;border-top:1px solid #ddd}.notice{border-left:4px solid #98a2b3;padding:12px 18px;background:#f4f6f8}p{overflow-wrap:anywhere}@media print{body{max-width:none;margin:0;font-size:10pt}nav,details{display:none}h2,h3{break-after:avoid}tr{break-inside:avoid}thead{display:table-header-group}.table-wrap{overflow:visible}a{color:inherit;text-decoration:none}}
</style></head><body><h1>Результаты технической проверки сайта</h1>'''+f'''<p>{esc(result.get('target'))}</p><p class="badge" style="background:{css}">{color} · {status}</p><p>Сканирование: {esc(result.get('scanner_version'))} · Завершено: {esc(result.get('finished_at'))}<br>Оформление отчёта: {esc(__version__)}. Дата со смещением +00:00 указана по UTC.</p><p class="notice">Цвет показывает технические замечания и полноту проверки. Зелёный не подтверждает соответствие законодательству; серый означает недостаточность данных. Юридическое заключение не формируется.</p><nav><a href="#summary">Итог</a><a href="#findings">Замечания</a><a href="#checks">Проверки</a><a href="#rules">Справочник правил</a><a href="#legal-matrix">Нормативные требования</a><a href="#inventory">Что найдено на сайте</a><a href="#limits">Ограничения</a></nav><h2 id="summary">Итог и полнота проверки</h2><p>Определённый результат получен для {esc(cov.get('completed',0))} из {esc(cov.get('planned',0))} применимых проверок. Это проверки правил, а не количество страниц и не доля всего сайта.</p><p>Обнаружено адресов: {esc(cov.get('known_urls',0))}; посещено уникальных адресов: {esc(cov.get('visited_urls',0))}; записей о пропуске: {esc(cov.get('skipped_urls',0))}. Один адрес может участвовать в нескольких правилах.</p>{summary}{partial}<h2 id="findings">Замечания и действия</h2>{findings or '<p>В выполненных проверках технические замечания не зафиксированы. Если проверка неполная, это не исключает проблем в непроверенной части.</p>'}<h2 id="checks">Результаты отдельных проверок</h2><p>Нажмите на код или название правила, чтобы перейти к его описанию ниже. Адреса с sha256 — замаскированные идентификаторы, не ссылки для открытия. Исходный путь по хешу восстановить нельзя.</p>{checks}{legal_matrix_html(result)}<h2 id="rules">Справочник правил</h2>{glossary}<h2 id="inventory">Что найдено на сайте</h2>{inventory_html(result['inventory'])}{browser_html(result.get("browser"))}<h2 id="limits">Ограничения проверки</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in result['limitations'])}</ul><h3>Пропущенные адреса</h3>{skipped}<footer><p>Отчёт основан на сохранённых наблюдениях. Повторное оформление не выполняет сканирование и не добавляет отсутствующие доказательства. Полные технические данные доступны в report.json.</p></footer></body></html>'''


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
    manifest['scope']=result['scope']
    if 'browser_options' in result:manifest['browser_options']=result['browser_options']
    manifest['files']=['report.json','report.html','sanitized.log']
    manifest['evidence_sha256']=list(result['evidence'])
    write_file(path/'manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2).encode())
    write_file(path/'sanitized.log',f"scan_status={result['scan_status']}\ncolor={result['color']}\nrequests={result['metrics']['requests']}\n".encode())
    return path
