from .presentation import esc,table,reason_text
LABELS={
'browser_total_byte_limit':'Исчерпан общий бюджет загрузки браузерного этапа.',
'browser_attempt_byte_limit':'Исчерпан бюджет загрузки этой попытки; следующая получает отдельный бюджет в пределах общего лимита.',
'browser_response_size_limit':'Отдельный ответ превышает лимит размера (HTML не более 2 МиБ; прочие ответы: --browser-response-mib).',
'byte_limit':'Исчерпан общий бюджет данных.',
'body_limit':'Достигнут лимит загрузки; старый отчёт не различает общий бюджет и размер ответа.',
'no_consent_elements':'Потенциальные элементы согласия в обследованном DOM не найдены.',
'no_eligible_button':'Потенциальные элементы найдены, но ни один не подходит для безопасного автоматического нажатия.',
'ambiguous_buttons':'Найдено несколько подходящих кнопок; выбор неоднозначен, нажатия не было.',
'diagnostic_limit':'Достигнут лимит анализа элементов; наблюдение неполно.',
'frames_not_inspected':'На странице есть iframe, их содержимое не обследовано.',
'browser_observation_incomplete':'Наблюдение не завершено; см. события и ограничения.',
'browser_not_started':'Сценарий не был запущен.',
'element_hidden':'Элемент скрыт.', 'element_disabled':'Элемент отключён.',
'element_in_form':'Элемент связан с формой; автоматическое нажатие исключено.',
'element_type_unsupported':'Тип элемента не поддержан для автоматического нажатия.',
'cookie_context_missing':'Не установлен контекст управления cookie.',
'action_label_mismatch':'Подпись не соответствует требуемому действию.',
'label_not_supported':'Подпись не входит в поддержанный список.',
}
ACTIONS={'reject':'Отказ','accept':'Согласие','revoke':'Отзыв'}
STAGES={'not_started':'Не запускался','load':'Загрузка','observe':'Наблюдение',**ACTIONS}
def describe(code):return LABELS.get(code) or reason_text(code)
def reasons_for(entry):
 if 'reasons' in entry:return entry['reasons']
 reasons=[entry['error']] if entry.get('error') else []
 reasons += [x['reason'] for x in entry.get('events',[]) if x.get('reason')]
 reasons += [x.get('reason') or 'no_eligible_button' for x in entry.get('actions',[]) if x['status']!='clicked']
 return list(dict.fromkeys(reasons))
def diagnostics_html(d):
 if not d:return '<p>Подробная диагностика элементов в исходном наблюдении не сохранена.</p>'
 rows=[]
 for c in d.get('candidates',[]):
  rows.append([c['index']+1,esc(c.get('kind','')),'Да' if c.get('visible') else 'Нет','Да' if c.get('associated') else 'Нет',esc(', '.join(ACTIONS.get(a,a) for a in c.get('recognized_actions',[])) or 'Не распознано'),esc('; '.join(describe(x) for x in c.get('reasons',[])) or 'Подходит по поддержанным признакам')])
 return '<p>Диагностика потенциальных элементов: кнопки, ссылки, checkbox/radio, ARIA button/checkbox/switch и select. Они не равнозначны полученному согласию; диагностическое обнаружение не означает автоматическое нажатие. Тексты подписей заменены хешами.</p>'+table(['№','Тип','Виден','Связан с подписью','Распознанное действие','Почему не нажат / признаки'],rows)

def legal_matrix_html(result):
 from collections import Counter
 from .legal import reference_text
 from .rules import RULES
 from .browser_rules import BROWSER_RULES
 from .presentation import OUTCOMES
 rules={**RULES,**BROWSER_RULES};groups={};unmapped=[]
 for c in result['checks']:
  basis=c.get('legal_basis')
  if not basis:unmapped.append(c);continue
  for n in basis:
   key=n['norm_id'];groups.setdefault(key,{'norm':n,'checks':[]})['checks'].append(c)
 rows=[]
 for group in groups.values():
  n=group['norm'];checks=group['checks'];ids=sorted({c['rule_id'] for c in checks});counts=Counter(c['outcome'] for c in checks)
  source=n.get('source_url','');link='<a href="'+esc(source)+'" rel="noreferrer">Источник</a>' if source.startswith(('http://','https://')) else ''
  rows.append([esc(reference_text([n]))+'<br>'+link,esc(n.get('obligation_summary','')),esc('Прямая обязанность при установленной применимости' if n.get('reference_kind')=='direct_requirement' else 'Общий правовой контекст технического наблюдения'),'<br>'.join(esc(k+' — '+rules.get(k,('',k))[1]) for k in ids),'<br>'.join(esc(OUTCOMES.get(k,k)+': '+str(v)) for k,v in counts.items()),'Выполнение или нарушение нормы не установлено. Применимость и недостающие доказательства указаны в отдельных проверках.'])
 out='<h2 id="legal-matrix">Нормативные требования и соответствующие проверки</h2><p>Таблица построена по нормативным ссылкам, сохранённым в этом отчёте. Она показывает связь нормы с техническими проверками, а не перечень норм, соответствие которым доказано. Числа — результаты проверок объектов, не количество нарушений закона.</p>'
 out+=table(['Закон, глава, статья, часть, пункт','Требование','Уровень связи','Проверки','Технические результаты','Правовой вывод'],rows)
 if unmapped:out+='<p>Без установленной нормативной привязки: '+str(len(unmapped))+' проверок ('+esc(', '.join(sorted({c['rule_id'] for c in unmapped})))+'). Причины приведены в строках проверок; для исторических отчётов отсутствующие нормы не добавляются.</p>'
 return out
