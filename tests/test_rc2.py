import io,json
from email.message import Message
from unittest import TestCase
from unittest.mock import patch,Mock
from pdscan.config import Config,ScanError
from pdscan.transport import Transport,Observation
from pdscan.rules import evaluate
from pdscan.browser import BrowserOptions,Gateway,new_entry,finalize,sanitize_diagnostics
from pdscan.browser_runner import failed
from pdscan.browser_rules import attach_browser
from pdscan.browser_diagnostics import legal_matrix_html
from pdscan.reporting import render_html
from pdscan.presentation import explain
from pdscan.cli import parser
from test_r2 import report,URL
class R2FixTests(TestCase):
 def read_response(self,size,budget,limit):
  payload=io.BytesIO(b'x'*size);response=Mock();response.status=200
  response.headers=Message();response.headers['Content-Type']='application/octet-stream'
  response.getheader.return_value=None;response.read=payload.read
  t=Transport(Config(URL,byte_limit=budget).validate())
  with patch('pdscan.transport.resolve_public'),patch('pdscan.transport.PinnedConnection') as conn:
   conn.return_value.getresponse.return_value=response
   return t.one(URL,limit),t
 def test_remaining_budget_not_double_counted(self):
  r,t=self.read_response(40000,60000,50000);self.assertEqual(len(r.body),40000);self.assertEqual(t.bytes,40000)
 def test_total_budget_has_distinct_code(self):
  with self.assertRaisesRegex(ScanError,'^byte_limit$'):self.read_response(70000,60000,90000)
 def test_response_limit_has_distinct_code(self):
  with self.assertRaisesRegex(ScanError,'^body_limit$'):self.read_response(40000,100000,30000)
 def test_browser_limits_parsed(self):
  a=parser().parse_args(['scan',URL,'--output','reports','--browser-total-mib','80','--browser-attempt-mib','20','--browser-response-mib','4'])
  self.assertEqual((a.browser_total_mib,a.browser_attempt_mib,a.browser_response_mib),(80,20,4))
 def test_limit_relationships(self):
  for kw in ({'total_mib':10},{'response_mib':30},{'total_mib':101},{'response_mib':True}):
   with self.assertRaises(ScanError):BrowserOptions(**kw).validate()
 def test_per_attempt_budget_restored_and_reset(self):
  gate=Gateway(Config(URL).validate(),BrowserOptions());route=Mock();route.request.method='GET';route.request.url=URL;route.request.resource_type='fetch';route.request.is_navigation_request.return_value=False
  gate.client.bytes=100;gate.start_attempt();events=[]
  def failure(*a):
   self.assertEqual(gate.client.config.byte_limit,100+25*1024**2);raise ScanError('byte_limit')
  with patch.object(gate.client,'check_robots'),patch.object(gate.client,'one',side_effect=failure):gate.handle(route,Mock(),events,['load'])
  self.assertEqual(events[0]['reason'],'browser_attempt_byte_limit');self.assertEqual(gate.client.config.byte_limit,100*1024**2)
  gate.client.bytes=200;gate.start_attempt();self.assertEqual(gate.attempt_start,200)
 def test_global_budget_stop(self):
  gate=Gateway(Config(URL).validate(),BrowserOptions());gate.client.bytes=100*1024**2;self.assertEqual(gate.stop_reason(),'browser_total_byte_limit')
 def test_pdf_both_attempts_not_applicable(self):
  o=Observation(URL,URL,200,b'pdf','application/pdf')
  for code in ('C01','C06'):self.assertEqual(evaluate(code,o,o)[0],'not_applicable')
 def test_pdf_html_disagreement_unknown(self):
  a=Observation(URL,URL,200,b'pdf','application/pdf');b=Observation(URL,URL,200,b'<html></html>','text/html')
  for code in ('C01','C06'):self.assertEqual(evaluate(code,a,b)[0],'inconclusive')
 def test_unknown_type_not_declared_inapplicable(self):
  o=Observation(URL,URL,200,b'other','application/octet-stream');self.assertEqual(evaluate('C06',o,o)[0],'inconclusive')
 def test_missing_browser_generates_all_attempts(self):
  r=report();attach_browser(r,failed('playwright_not_installed'),[URL]);self.assertEqual(len(r['browser']['scenarios']),8)
  for e in r['browser']['scenarios']:self.assertEqual(e['status'],'not_started');self.assertIn('playwright_not_installed',e['reasons'])
  html=render_html(r);self.assertIn('Невыполненные действия',html);self.assertIn('Не получено',html)
 def test_unperformed_revoke_after_unsupported_accept(self):
  e=new_entry(URL,'S3',1);e['status']='unsupported';e['actions']=[{'action':'accept','status':'unsupported','reason':'ambiguous_buttons'}]
  finalize({'scenarios':[e]});self.assertEqual(e['not_performed'],['accept','revoke']);self.assertIn('ambiguous_buttons',e['reasons'])
 def test_action_succeeded_but_observation_partial(self):
  e=new_entry(URL,'S3',1);e['status']='partial';e['actions']=[{'action':'accept','status':'clicked'}];e['events']=[{'reason':'browser_attempt_byte_limit'}]
  finalize({'scenarios':[e]});self.assertEqual(e['not_performed'],['revoke']);self.assertIn('browser_attempt_byte_limit',e['reasons'])
 def test_diagnostic_labels_never_saved(self):
  r=sanitize_diagnostics({'candidates':[{'index':0,'label':'SECRET email@example.org','kind':'button','reasons':['element_in_form']}]})
  self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('email@example.org',json.dumps(r));self.assertIn('label_hash',r['candidates'][0])
 def test_normative_matrix_uses_saved_evidence(self):
  r=report();html=legal_matrix_html(r);self.assertIn('152-ФЗ',html);self.assertIn('ст. 19',html);self.assertIn('C01',html)
  for c in r['checks']:c.pop('legal_basis',None)
  self.assertNotIn('ст. 19',legal_matrix_html(r))
 def test_pdf_reason_displayed(self):
  c={'rule_id':'C06','outcome':'not_applicable','message':'Получен PDF: проверка HTML неприменима.'};self.assertEqual(explain(c,{}),c['message'])
 def test_killed_worker_does_not_claim_no_actions(self):
  r=report();attach_browser(r,failed('browser_timeout'),[URL])
  for e in r['browser']['scenarios']:self.assertEqual(e['status'],'observation_lost');self.assertTrue(e['actions_status_unknown']);self.assertEqual(e['not_performed'],[])
  self.assertIn('Неизвестно: наблюдения потеряны',render_html(r))
