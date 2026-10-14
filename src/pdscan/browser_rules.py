from copy import deepcopy
from collections import defaultdict
from .evidence import artifact,token
from .legal import browser_fields

BROWSER_RULES={
'B01':('M02','Документы в отображаемой странице','Фиксирует ссылки после выполнения JavaScript; отсутствие распознанной ссылки не доказывает отсутствие документа.'),
'B02':('M07','Связь элемента выбора с согласием','Фиксирует связь label/aria с выбором и ссылками; неизвестный компонент остаётся неопределённым.'),
'B03':('M08','Совместное принятие документов','Ищет ограниченные явные формулировки согласия вместе с принятием оферты; ссылка на политику сама по себе не является замечанием.'),
'B04':('M09','Выбор до действия пользователя','Фиксирует установленный флажок согласия до нажатий сканера. Это не доказательство отсутствия действительного согласия.'),
'B05':('M10','Выбор рекламных сообщений','Наблюдает рекламную формулировку и её связь с элементом выбора; рассылка не выполняется.'),
'B06':('M12','Сценарии cookie и запросов','Сравнивает S0–S3 в отдельных чистых контекстах. Попытка запроса не равна передаче ПДн; назначение cookie не устанавливается.')}

def decide(rule,entries):
    s0=[e for e in entries if e['scenario']=='S0']
    if len(s0)!=2 or any(not e.get('snapshot') for e in s0):return 'not_checked','Нет двух пригодных снимков исходной страницы.'
    first,second=[e['snapshot'] for e in s0]
    a,b=[s.get('controls',[]) for s in (first,second)]
    if rule=='B01':
        if first['documents']!=second['documents']:return 'inconclusive','Ссылки в двух загрузках различаются.'
        return ('pass',f"В двух загрузках найдено ссылок на документы: {len(first['documents'])}. Содержание не проверялось.") if first['documents'] else ('inconclusive','Распознанные ссылки не найдены в обследованной странице; отсутствие документов не установлено.')
    if rule=='B06':
        if len(entries)!=8 or any(e['status']!='complete' for e in entries):return 'inconclusive','Не все S0–S3 завершены: см. сценарии, блокировки и неподдержанные кнопки.'
        return 'pass','Сценарии выполнены по две попытки; различия показаны отдельно. Законность запросов не определялась.'
    if a!=b:return 'inconclusive','Состояния элементов в двух загрузках различаются.'
    relevant=[x for x in a if x.get('consent') and x.get('visible') and not x.get('negative')]
    if rule=='B05':
        marketing=[x for x in a if x.get('marketing') and x.get('visible')]
        if not marketing:return 'inconclusive','Явно обозначенный рекламный выбор не распознан; его обязательность не установлена.'
        return 'pass',f'Наблюдается рекламных элементов выбора: {len(marketing)}; совмещённых с формулировкой о ПДн: {sum(bool(x.get("consent")) for x in marketing)}. Требуется проверка цели и текста.'
    if not relevant:return 'inconclusive','Распознанный элемент согласия не найден; иное правовое основание или иной интерфейс не исключены.'
    if rule=='B02':
        if all(x.get('association') and x.get('links') for x in relevant):return 'pass','Наблюдается явная связь выбора с подписью и ссылкой. Содержимое ссылки не проверялось.'
        return 'inconclusive','Не для каждого распознанного выбора найдена явная связанная ссылка. Это не доказательство отсутствия согласия.'
    if rule=='B03':
        return ('fail','В двух загрузках одна подпись выбора содержит согласие на ПДн и явное принятие оферты. Проверить отдельность оформления.') if any(x.get('combined') for x in relevant) else ('pass','Поддержанные явные формулировки совместного принятия не найдены. Произвольные тексты не оценивались.')
    if rule=='B04':
        if any(x.get('checked') is True for x in relevant):return 'fail','В двух загрузках выбор согласия установлен до действия сканера. История и основание согласия неизвестны.'
        if any(x.get('checked') is None for x in relevant):return 'inconclusive','Не удалось прочитать состояние нестандартного элемента выбора.'
        return 'pass','Распознанные элементы согласия не отмечены до действий сканера.'
    return 'not_checked','Неизвестное правило.'

def scenario_comparison(entries):
    out=[]
    for attempt in (1,2):
        group={e['scenario']:e for e in entries if e['attempt']==attempt}
        base=group.get('S0',{})
        def identities(e):return {x['url'] for x in e.get('events',[]) if x.get('delivery')=='received'}
        def cookies(e):return {(x['name'],x['domain'],x['path']) for x in e.get('cookies',[])}
        for s in ('S1','S2','S3'):
            e=group.get(s,{})
            out.append({'scenario':s,'attempt':attempt,'comparable':base.get('status')=='complete' and e.get('status')=='complete','received_added':sorted(identities(e)-identities(base)),'received_removed':sorted(identities(base)-identities(e)),'cookies_added':len(cookies(e)-cookies(base)),'cookies_removed':len(cookies(base)-cookies(e)),'post_action_attempts':sum(x.get('phase') in ('reject','accept','revoke') for x in e.get('events',[])),'post_action_received':sum(x.get('phase') in ('reject','accept','revoke') and x.get('delivery')=='received' for x in e.get('events',[]))})
    return out

def attach_browser(result,browser,urls):
    result['browser']=browser
    groups=defaultdict(list)
    for e in browser['scenarios']:groups[e['url']].append(e)
    from .evidence import safe_url
    for u in urls:groups.setdefault(safe_url(u),[])
    browser['comparisons']=[]
    for url,entries in groups.items():
        refs=[]
        for e in entries:
            ev=artifact(e);result['evidence'][ev['sha256']]=ev;refs.append(ev['sha256'])
        browser['comparisons'].append({'url':url,'changes':scenario_comparison(entries)})
        for rule,(matrix,name,_) in BROWSER_RULES.items():
            outcome,fact=decide(rule,entries)
            if outcome=='pass' and any(e.get('status')!='complete' for e in entries if e['scenario']=='S0'):
                outcome='inconclusive';fact+=' Загрузка была ограничена; положительный итог не установлен.'
            c={'rule_id':rule,'matrix_id':matrix,'machine_key':rule.lower()+'-v1','url':url,'outcome':outcome,'reason_code':outcome,'fact':fact,'message':fact,'object_kind':'browser','evidence_refs':refs,**browser_fields(rule,outcome)}
            result['checks'].append(c)
            if outcome=='fail':result['findings'].append({'finding_id':token(rule+url),'rule_id':rule,'url':url,'fact':fact,'technical_severity':'medium','color':'yellow','recommendation':'Проверьте конкретный элемент и связанный документ; правовой вывод требует установления основания обработки.','evidence_refs':refs,**browser_fields(rule,outcome)})
    if browser['status']!='complete':result['scan_status']='partial'
    if browser.get('error')=='cancelled':result['scan_status']='cancelled'
    result['limitations'].extend(browser['limitations'])
    applicable=[x for x in result['checks'] if x['outcome']!='not_applicable']
    completed=sum(x['outcome'] in ('pass','fail') for x in applicable)
    result['coverage'].update(completed=completed,planned=len(applicable),ratio=completed/len(applicable) if applicable else None)
    if any(x['outcome'] in ('not_checked','inconclusive') for x in result['checks']) and result['scan_status']=='complete':result['scan_status']='partial'
    colors={x['color'] for x in result['findings']}
    result['color']='red' if 'red' in colors else 'yellow' if 'yellow' in colors else 'grey' if result['scan_status']!='complete' else 'green'
    result['legal_catalog']['norms']=list({n['norm_id']:n for c in result['checks'] for n in c['legal_basis']}.values())
    return result
