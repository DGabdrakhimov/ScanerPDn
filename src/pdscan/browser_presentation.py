from .presentation import esc,table,reason_text
from .legal import reference_text
from .browser_diagnostics import describe,reasons_for,diagnostics_html,ACTIONS,STAGES

def legal_html(item):
 if 'legal_basis' not in item:return '<p><small>В исходном отчёте правовая привязка не сохранена. При переоформлении она не добавляется.</small></p>'
 norms=item['legal_basis']
 status={'not_checked':'Не проверено','insufficient_data':'Недостаточно данных'}.get(item.get('legal_status'),'Не определено')
 text='<p><b>Правовое основание:</b> '+esc(reference_text(norms))+'<br><b>Правовой статус:</b> '+status+'<br>'+esc(item.get('legal_reason',''))+'</p>'
 text+='<details><summary>Применимость, источники и недостающие сведения</summary><p>'+esc(item.get('applicability',{}).get('condition',''))+'</p><ul>'+''.join('<li>'+esc(x)+'</li>' for x in item.get('missing_evidence',[]))+'</ul>'
 for n in norms:
  url=n.get('source_url','')
  text+='<p>'+esc(n.get('obligation_summary',''))+'<br>Редакция нормы: '+esc(n.get('edition_date') or 'не установлена')+'; вступление: '+esc(n.get('effective_from') or 'не установлено')+'; сверка: '+esc(n.get('checked_at',''))+'.<br>'
  text+=('<a href="'+esc(url)+'" rel="noreferrer">Источник нормы</a>' if url.startswith(('https://','http://')) else 'Источник не задан')+'</p>'
 return text+'</details>'

def browser_html(browser):
 if not browser:return ''
 from .browser import SCENARIOS
 statuses={'complete':'Выполнен в заданном объёме','partial':'Частичный','unsupported':'Действие не выполнено','not_started':'Не запускался','observation_lost':'Наблюдения потеряны'}
 out='<h2 id="browser">Браузерные сценарии R2</h2><p>Каждый сценарий начинается с чистого контекста и выполняется дважды. S3: согласие, затем отзыв в том же контексте. Заблокированный запрос — попытка, а не подтверждённая передача.</p>'
 if browser.get('limits'):
  limits=browser['limits'];out+='<p>Бюджеты: весь этап '+str(limits['total_mib'])+' МиБ; одна попытка '+str(limits['attempt_mib'])+' МиБ; отдельный ответ '+str(limits['response_mib'])+' МиБ (HTML — '+str(limits.get('html_mib',2))+' МиБ).</p>'
 if browser.get('error'):out+='<p>Причина незавершения: '+esc(reason_text(browser['error']))+' ('+esc(browser['error'])+').</p>'
 rows=[]
 for e in browser.get('scenarios',[]):
  rows.append([esc(e['url']),esc(e['scenario']+' · '+SCENARIOS[e['scenario']]),e['attempt'],statuses.get(e['status'],'Не определено'),esc('; '.join(describe(x) for x in reasons_for(e)) or 'Нет причин незавершения, сохранённых в отчёте'),esc('Неизвестно: наблюдения потеряны' if e.get('actions_status_unknown') else ', '.join(ACTIONS.get(a,a) for a in e.get('not_performed',[])) or ('Нет' if 'not_performed' in e else 'Не сохранено')),len(e.get('cookies',[])) if e.get('snapshot') else 'Не получено',len(e.get('snapshot',{}).get('storage',[])) if e.get('snapshot') else 'Не получено',esc('; '.join(ACTIONS.get(a['action'],a['action'])+': '+('нажата' if a['status']=='clicked' else 'однозначная кнопка не найдена') for a in e.get('actions',[])) or 'Без нажатий')])
 out+=table(['Объект','Сценарий','Попытка','Результат','Причины незавершения','Невыполненные действия','Cookie','Ключи localStorage','Действия'],rows)
 for e in browser.get('scenarios',[]):
  out+='<details><summary>'+esc(e['scenario'])+' · попытка '+str(e['attempt'])+' · запросы и найденные элементы</summary>'
  out+='<p>Последний этап: '+esc(STAGES.get(e.get('stage'), 'В старом отчёте не сохранён'))+'.</p>'
  out+=diagnostics_html(e.get('diagnostics'))
  for action in e.get('actions',[]):
   out+='<h4>Диагностика действия: '+esc(ACTIONS.get(action['action'],action['action']))+'</h4>'+diagnostics_html(action)
  rows=[[esc(x['url']),esc(x['method']),esc(x['phase']),'Ответ получен' if x['delivery']=='received' else 'Заблокировано',esc(x.get('status','')),esc(describe(x['reason'])) if x.get('reason') else ''] for x in e.get('events',[])]
  out+=table(['Идентификатор адреса','Метод','Этап','Доставка','Код ответа','Причина'],rows)
  snapshot=e.get('snapshot',{})
  out+=table(['Элемент','Виден','Выбран','Признак согласия','Рекламная формулировка','Связанных ссылок'],[[x['index']+1,'Да' if x['visible'] else 'Нет','Да' if x['checked'] is True else 'Нет' if x['checked'] is False else 'Неизвестно','Да' if x['consent'] else 'Нет','Да' if x['marketing'] else 'Нет',len(x['links'])] for x in snapshot.get('controls',[])])
  out+=table(['Ссылка после JavaScript','Тип по подписи'],[[esc(x['url']),{'policy':'Политика','consent':'Согласие','unknown':'Не определён'}.get(x['type'],'Не определён')] for x in snapshot.get('documents',[])])
  out+=table(['Идентификатор cookie','Только HTTPS','Недоступна JavaScript','SameSite'],[[esc(x['name']),'Да' if x['secure'] else 'Нет','Да' if x['httponly'] else 'Нет',esc(x.get('samesite',''))] for x in e.get('cookies',[])])
  cp=e.get('checkpoints',{})
  if 'accept' in cp and 'revoke' in cp:
   def cookie_ids(c):return {(x['name'],x['domain'],x['path']) for x in c.get('cookies',[])}
   removed=len(cookie_ids(cp['accept'])-cookie_ids(cp['revoke']))
   added=len(cookie_ids(cp['revoke'])-cookie_ids(cp['accept']))
   out+='<p>В S3 между согласием и отзывом: исчезло cookie '+str(removed)+', появилось '+str(added)+'. Значения cookie не сравниваются; прекращение обработки не установлено.</p>'
  out+='</details>'
 rows=[]
 for group in browser.get('comparisons',[]):
  for x in group['changes']:rows.append([esc(group['url']),esc(x['scenario']),x['attempt'],'Да' if x['comparable'] else 'Ограниченно',len(x['received_added']),len(x['received_removed']),x['cookies_added'],x['cookies_removed'],x['post_action_attempts'],x['post_action_received']])
 out+='<h3>Изменения относительно S0</h3>'+table(['Объект','Сценарий','Попытка','Все этапы завершены','Новых адресов','Исчезнувших адресов','Новых cookie','Исчезнувших cookie','Попыток после действий','Получено ответов после действий'],rows)
 return out
