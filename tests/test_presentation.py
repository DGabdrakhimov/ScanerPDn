import unittest
from copy import deepcopy
from pathlib import Path
import tempfile,json
from unittest.mock import patch
from test_system import FakeTransport,page
from pdscan.config import Config
from pdscan.core import scan
from pdscan.presentation import explain,inventory_html,RULE_HELP
from pdscan.reporting import render_html
from pdscan.cli import main

class PresentationTests(unittest.TestCase):
 def setUp(self):
  self.cfg=Config('https://example.org/')
  self.result=scan(self.cfg,transport=FakeTransport(self.cfg,{self.cfg.target:page(self.cfg.target,'<html><p>Hello</p></html>')}))
 def check(self,rule):return next(c for c in self.result['checks'] if c['rule_id']==rule)
 def test_context_saved(self):
  self.assertEqual(self.check('C06')['object_kind'],'page');self.assertIn('message',self.check('C06'))
 def test_pass_explanation(self):self.assertIn('HTTPS',explain(self.check('C01'),self.result))
 def test_not_applicable_form(self):self.assertIn('не найдено',explain(self.check('C06'),self.result))
 def test_legacy_na_no_invention(self):
  c=deepcopy(self.check('C06'));c.pop('object_kind');self.assertIn('старом отчёте',explain(c,self.result))
 def test_document_na(self):self.assertIn('обычная страница',explain(self.check('C03'),self.result))
 def test_glossary_all_links(self):
  h=render_html(self.result)
  for r in RULE_HELP:self.assertIn('id="rule-'+r+'"',h);self.assertIn('href="#rule-'+r+'"',h)
 def test_coverage_not_pages(self):self.assertIn('не количество страниц',render_html(self.result))
 def test_status_russian(self):self.assertIn('Завершена в заданных пределах',render_html(self.result))
 def test_empty_inventory_is_not_absence(self):self.assertIn('не доказывает отсутствие',inventory_html(self.result['inventory']))
 def test_inventory_tables_escape(self):
  inv={'documents':[{'label':'<script>alert(1)</script>','url':'<img>','source':'x','explicit':True}], 'forms':[{'page':'x','index':0,'fields':[{'type':'email'},{'type':'checkbox'}],'action':None}], 'cookies':[{'source':'x','name':'<img>','secure':False,'httponly':True,'samesite':'lax'}], 'external_hosts':['<script>']}
  h=inventory_html(inv);self.assertNotIn('<script>',h);self.assertNotIn('<pre>',h);self.assertIn('Электронная почта',h);self.assertIn('Флажок выбора',h);self.assertIn('флаг не задан',h)
 def test_unknown_reason(self):
  c=deepcopy(self.check('C01'));c.update(outcome='inconclusive',reason_code='new_error',evidence_refs=[])
  self.assertIn('недостаточно',explain(c,self.result))
 def test_http403_explained(self):
  c=self.check('C01');c.update(outcome='inconclusive',reason_code='inconsistent_or_unavailable')
  for ref in c['evidence_refs']:self.result['evidence'][ref]['data']['status']=403
  self.assertIn('Доступ запрещён',explain(c,self.result))
 def test_network_failure_translated(self):
  c=self.check('C01');c.update(outcome='inconclusive',reason_code='dns_timeout')
  for ref in c['evidence_refs']:self.result['evidence'][ref]['data']['error']='dns_timeout'
  self.assertIn('определения сетевого адреса',explain(c,self.result))
 def test_partial_with_no_skipped(self):
  self.result['scan_status']='partial';self.check('C01')['outcome']='inconclusive'
  h=render_html(self.result);self.assertIn('Почему проверка неполная',h);self.assertIn('Пропущенных адресов в отчёте нет',h)
 def test_render_does_not_mutate(self):
  before=deepcopy(self.result);render_html(self.result);self.assertEqual(before,self.result)
 def test_old_json_render_offline(self):
  for c in self.result['checks']:c.pop('message');c.pop('object_kind')
  self.result['scanner_version']='0.1.0rc1'
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'report.json';p.write_text(json.dumps(self.result)); original=p.read_bytes()
   with patch('socket.create_connection',side_effect=AssertionError('network')):
    self.assertEqual(main(['render',str(p)]),0)
   self.assertEqual(p.read_bytes(),original);self.assertIn('0.1.0rc1',(p.with_suffix('.html')).read_text())
 def test_failure_fact(self):
  c=self.check('C01');c['outcome']='fail';self.result['findings']=[{'rule_id':'C01','url':c['url'],'fact':'Страница получена по HTTP.'}]
  self.assertEqual(explain(c,self.result),'Страница получена по HTTP.')
 def test_cookie_lifetime(self):
  h=inventory_html({'cookies':[{'max_age':0},{'expires_present':True}]})
  self.assertIn('Команда удалить',h);self.assertIn('не распознана',h)
