import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock
from pdscan.config import Config
from pdscan.core import scan
from pdscan.browser import BrowserOptions,Gateway,sanitized_snapshot,cookie_metadata
from pdscan.browser_runner import failed
from pdscan.browser_rules import decide,attach_browser,scenario_comparison
from pdscan.comparison import compare_reports,comparison_html
from pdscan.reporting import render_html,validate_report
from pdscan.legal import legal_fields,browser_fields
from pdscan.cli import main
from test_system import FakeTransport,page

URL='https://example.org/'
def report(body='',routes=None):
 c=Config(URL).validate()
 return scan(c,transport=FakeTransport(c,{URL:page(URL,body),**(routes or {})}))
def entries(control=None):
 snapshot={'controls':[control] if control else [],'documents':[],'storage':[],'limited':False,'frames':0}
 return [{'url':URL,'scenario':s,'attempt':i,'status':'complete','snapshot':deepcopy(snapshot),'cookies':[],'events':[],'actions':[]} for s in ('S0','S1','S2','S3') for i in (1,2)]

class R2Tests(unittest.TestCase):
 def test_legal_policy_context(self):
  r=report('<a href="/policy">Политика конфиденциальности</a>',{URL+'policy':page(URL+'policy','',404)})
  checks=[x for x in r['checks'] if x['rule_id']=='C03' and x['object_kind']=='document']
  self.assertEqual(checks[0]['legal_basis'][0]['article'],'18.1')
  self.assertEqual(checks[0]['legal_status'],'insufficient_data')
 def test_late_conflicting_document_types(self):
  r=report('<a href="/doc">Политика конфиденциальности</a><a href="/next">next</a>',{URL+'doc':page(URL+'doc','',404),URL+'next':page(URL+'next','<a href="/doc">Согласие на обработку персональных данных</a>')})
  for c in r['checks']:
   if c['object_kind']=='document' and c['rule_id']=='C03':self.assertEqual(c['legal_basis'],[])
 def test_no_consent_duty_from_unclassified_url(self):
  self.assertEqual(legal_fields('C03','fail')['legal_basis'],[])
 def test_conflicting_aria_label(self):
  from pdscan.extractors import extract
  x=extract(page(URL,'<a href="/doc" aria-label="Согласие на обработку персональных данных">Политика конфиденциальности</a>'))
  self.assertEqual(x['links'][0]['document_type'],'unknown')
 def test_legal_null_verdict(self):
  for rule in ('B01','B02','B03','B04','B05','B06'):
   for outcome in ('pass','fail','inconclusive','not_checked'):
    f=browser_fields(rule,outcome);self.assertIsNone(f['legal_verdict']);self.assertNotIn(f['legal_status'],('fulfilled','violated'))
 def test_prechecked_twice(self):
  e=entries({'consent':True,'visible':True,'checked':True})
  self.assertEqual(decide('B04',e)[0],'fail')
  e[1]['snapshot']['controls'][0]['checked']=False
  self.assertEqual(decide('B04',e)[0],'inconclusive')
 def test_combined_vs_policy_link(self):
  e=entries({'consent':True,'visible':True,'combined':False})
  self.assertEqual(decide('B03',e)[0],'pass')
  for x in e:x['snapshot']['controls'][0]['combined']=True
  self.assertEqual(decide('B03',e)[0],'fail')
 def test_scenario_failure_prevents_pass(self):
  e=entries();e[-1]['status']='unsupported'
  self.assertEqual(decide('B06',e)[0],'inconclusive')
 def test_empty_browser_keeps_http(self):
  r=report();before=deepcopy(r['checks']);attach_browser(r,failed('playwright_not_installed'),[URL])
  self.assertEqual(r['checks'][:len(before)],before);self.assertEqual(len(r['checks']),len(before)+6)
  self.assertEqual(r['color'],'grey');self.assertIn('Браузерные сценарии',render_html(r))
 def test_masking(self):
  raw={'controls':[{'label':'private-secret','links':[{'url':URL+'private-secret?token=private-secret','label':'private-secret'}]}],'storage':['private-secret'],'documents':[]}
  self.assertNotIn('private-secret',json.dumps(sanitized_snapshot(raw)))
  self.assertNotIn('private-secret',json.dumps(cookie_metadata([{'name':'private-secret','value':'private-secret','domain':'private-secret','path':'private-secret'}])))
 def test_gateway_post_blocked_before_transport(self):
  gate=Gateway(Config(URL).validate(),BrowserOptions());route=Mock();route.request.method='POST';route.request.url=URL;route.request.resource_type='fetch';events=[]
  with patch.object(gate.client,'one') as one:gate.handle(route,Mock(),events,['accept']);one.assert_not_called()
  route.abort.assert_called_once();self.assertEqual(events[0]['reason'],'browser_method_blocked')
 def test_gateway_scope_query(self):
  for url in ('https://other.org/',URL+'?token=secret'):
   gate=Gateway(Config(URL).validate(),BrowserOptions());route=Mock();route.request.method='GET';route.request.url=url;route.request.resource_type='fetch';route.request.is_navigation_request.return_value=False;events=[]
   with patch.object(gate.client,'one') as one:gate.handle(route,Mock(),events,['load']);one.assert_not_called()
   self.assertEqual(events[0]['delivery'],'blocked');self.assertNotIn('secret',json.dumps(events))
 def test_gateway_private_dns(self):
  from pdscan.config import ScanError
  gate=Gateway(Config(URL).validate(),BrowserOptions());route=Mock();route.request.method='GET';route.request.url=URL;route.request.resource_type='fetch';route.request.is_navigation_request.return_value=False;events=[]
  with patch.object(gate.client,'check_robots'),patch('pdscan.transport.resolve_public',side_effect=ScanError('blocked_address')):
   gate.handle(route,Mock(),events,['load'])
  self.assertEqual(events[0]['reason'],'blocked_address');route.fulfill.assert_not_called()
 def test_blocked_is_not_received(self):
  e=entries();e[2]['events']=[{'url':URL,'delivery':'blocked','phase':'reject'}]
  x=scenario_comparison(e)[0];self.assertEqual(x['post_action_attempts'],1);self.assertEqual(x['post_action_received'],0)
 def test_comparison_changed_coverage(self):
  a=report();b=deepcopy(a);b['checks'].pop();c=compare_reports(a,b)
  self.assertIsNone(c['changes'][0]['after']);self.assertIn('Нет проверки',comparison_html(c))
 def test_old_schema_no_legal_backfill(self):
  r=report();r['schema_version']='1.0'
  for c in r['checks']:c.pop('legal_basis')
  self.assertIn('правовая привязка не сохранена',render_html(r))
 def test_new_schema_requires_legal(self):
  r=report();r['checks'][0].pop('legal_basis')
  with self.assertRaises(ValueError):validate_report(r)
 def test_cli_combined_checkpoint(self):
  r=report()
  with tempfile.TemporaryDirectory() as temp,patch('pdscan.cli.scan',return_value=r),patch('pdscan.cli.run_isolated',return_value=failed('browser_timeout')),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   code=main(['scan',URL,'--mode','combined','--output',temp])
   self.assertEqual(code,3);self.assertTrue((Path(temp)/'r1'/'report.html').is_file())
   final=json.loads((Path(temp)/'report.json').read_text());self.assertEqual(final['browser']['error'],'browser_timeout')
 def test_legal_html_escapes(self):
  r=report();r['checks'][0]['legal_reason']='<script>alert(1)</script>'
  self.assertNotIn('<script>',render_html(r));self.assertIn('&lt;script&gt;',render_html(r))
 def test_options_bounds(self):
  from pdscan.config import ScanError
  for kw in ({'pages':0},{'max_requests':1},{'wait_ms':99999},{'time_limit':0}):
   with self.assertRaises(ScanError):BrowserOptions(**kw).validate()
