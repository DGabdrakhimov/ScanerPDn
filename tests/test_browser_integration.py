"""Real Chromium tests, offline fixtures. Explicit skips when browser is absent."""
from pathlib import Path
import unittest
from unittest.mock import patch
from pdscan.browser import Gateway,BrowserOptions,run_browser
from pdscan.config import Config
from pdscan.transport import Response

FIXTURE='''<!doctype html><meta charset="utf-8">
<a href="/policy">Политика конфиденциальности</a>
<label><input type="checkbox" checked>Я согласен на обработку персональных данных и принимаю оферту <a href="/consent">Документ</a></label>
<div id="cookie-box">Cookie
<button type="button" onclick="localStorage.setItem('choice','no')">Отклонить все</button>
<button type="button" onclick="document.cookie='accepted=1; path=/';localStorage.setItem('choice','yes')">Принять все</button>
<button type="button" onclick="document.cookie='accepted=; Max-Age=0; path=/';localStorage.removeItem('choice')">Отозвать согласие</button></div>
<script>fetch('/submit',{method:'POST',body:'test-value'}).catch(()=>{});</script>'''

class BrowserIntegrationTests(unittest.TestCase):
 def test_chromium_scenarios_and_dom(self):
  try:from playwright.sync_api import sync_playwright
  except ImportError:self.skipTest('Playwright не установлен; реальный браузер не проверен')
  with sync_playwright() as pw:
   if not Path(pw.chromium.executable_path).exists():
    # headless-shell-only installations have another executable path.
    try:b=pw.chromium.launch();b.close()
    except Exception:self.skipTest('Chromium недоступен; реальный браузер не проверен')
  config=Config('https://example.org/').validate();options=BrowserOptions(wait_ms=100)
  gate=Gateway(config,options)
  with patch.object(gate.client,'check_robots'),patch.object(gate.client,'one',return_value=Response(config.target,200,FIXTURE.encode(),content_type='text/html')):
   result=run_browser(config,[config.target],options,gateway=gate)
  self.assertIsNone(result['error'])
  self.assertEqual(len(result['scenarios']),8)
  for e in result['scenarios']:
   self.assertTrue(e['snapshot']['controls'][0]['checked'])
   self.assertTrue(e['snapshot']['controls'][0]['combined'])
   self.assertEqual(e['before']['storage'],[]) # Every context starts clean.
   self.assertTrue(any(x['method']=='POST' and x['delivery']=='blocked' for x in e['events']))
   self.assertEqual(e['status'],'partial') # Blocked POST must not disappear.
   if e['scenario']=='S3':
    self.assertEqual(len(e['checkpoints']['accept']['cookies']),1)
    self.assertEqual(e['checkpoints']['revoke']['cookies'],[])
