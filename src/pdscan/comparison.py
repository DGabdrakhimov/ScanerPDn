"""Offline comparison of recorded outcomes, without inventing resolved violations."""
from collections import defaultdict

def compare_reports(before,after):
 from .reporting import validate_report
 validate_report(before);validate_report(after)
 if before['target']!=after['target']:raise ValueError('different_targets')
 def index(r):
  out=defaultdict(list)
  for c in r['checks']:
   key=(c['rule_id'],c['url'],c.get('object_kind','legacy'))
   out[key].append(c['outcome'])
  return {k:sorted(v) for k,v in out.items()}
 old,new=index(before),index(after)
 changes=[]
 for key in sorted(old.keys()|new.keys()):
  if old.get(key)==new.get(key):continue
  changes.append({'rule_id':key[0],'url':key[1],'object_kind':key[2],'before':old.get(key),'after':new.get(key),'meaning':'Изменение сохранённых наблюдений; исчезновение проверки не означает устранение проблемы.'})
 comparable=all(before.get(k)==after.get(k) for k in ('ruleset_version','config','scope')) and before.get('browser_options')==after.get('browser_options')
 return {'comparison_version':'1.0','before_scan_id':before['scan_id'],'after_scan_id':after['scan_id'],'same_settings_and_rules':comparable,'changes':changes,'note':'Сравниваются технические исходы, а не юридическое соответствие. При разных настройках и правилах результаты не равнозначны; изменившийся охват учитывайте отдельно.'}


def comparison_html(result):
 from .presentation import esc,table,OUTCOMES
 def label(values):return 'Нет проверки' if values is None else ', '.join(OUTCOMES.get(x,x) for x in values)
 rows=[[esc(c['rule_id']),esc(c['url']),esc(label(c['before'])),esc(label(c['after']))] for c in result['changes']]
 return '<!doctype html><html lang="ru"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Сравнение PDScan</title><style>body{font:16px/1.6 system-ui;margin:30px}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:10px;overflow-wrap:anywhere}</style><h1>Сравнение наблюдений</h1><p>'+esc(result['note'])+'</p><p>Настройки и правила совпадают: '+('да' if result['same_settings_and_rules'] else 'нет')+'</p>'+table(['Правило','Объект','Раньше','Теперь'],rows)+('<p>Изменений исходов не найдено.</p>' if not rows else '')+'</html>'
