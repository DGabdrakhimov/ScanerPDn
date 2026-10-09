import contextlib
from copy import deepcopy
import gzip
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pdscan.config import Config, ScanError, normalize_url
from pdscan.transport import Transport, Observation, Hop, public_ip, resolve_public, Response, PinnedConnection
from pdscan.core import scan
from pdscan.extractors import extract, cookies_inventory
from pdscan.evidence import safe_url
from pdscan.reporting import render,render_html
from pdscan.cli import main,exit_code


def page(url,body,status=200):
 return Observation(url,url,status,body.encode(),'text/html',chain=[Hop(url,status)])

class FakeTransport:
 def __init__(self,c,routes,interrupt=False):self.c=c;self.routes=routes;self.requests=0;self.bytes=0;self.calls=[];self.interrupt=interrupt
 def fetch(self,url,document=False):
  if self.interrupt:raise KeyboardInterrupt
  self.requests+=1;self.calls.append(url)
  obj=self.routes.get(url,Observation(url,url,error='not_available'))
  o=deepcopy(obj);self.bytes+=len(o.body);return o
 def allowed(self,u,external=False):return Transport.allowed(self,u,external)
 @property
 def config(self):return self.c
 @property
 def blocked_hosts(self):return set()
 def remaining(self):return 300

class SecurityTests(unittest.TestCase):
 def test_addresses(self):
  for ip in ['127.0.0.1','0.0.0.0','10.1.2.3','172.16.0.1','192.168.0.1','169.254.169.254','100.64.0.1','224.0.0.1','255.255.255.255','::1','::','fc00::1','fe80::1','ff02::1','::ffff:8.8.8.8','2002:0808:0808::1','64:ff9b::808:808','64:ff9b:1::1']:
   with self.subTest(ip=ip):self.assertFalse(public_ip(ip))
  self.assertTrue(public_ip('8.8.8.8'));self.assertTrue(public_ip('2606:4700:4700::1111'))
 def test_invalid_url(self):
  for u in ['file:///etc/passwd','ftp://example.org','https://u:p@example.org','https://example.org:8443','http://127.1','http://2130706433','http://0x7f000001','http://0177.0.0.1','https://example.org\\@127.0.0.1','https://example.org/\r\nX:y','http://[fe80::1%25eth0]/']:
   with self.subTest(url=u),self.assertRaises(ScanError):normalize_url(u)
 def test_canonical(self):
  self.assertEqual(normalize_url('HTTPS://EXAMPLE.ORG:443/a#b'),'https://example.org/a')
  self.assertIn('xn--',normalize_url('https://пример.рф/'))
 def test_mixed_dns(self):
  entries=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]
  with patch('socket.getaddrinfo',return_value=entries),self.assertRaisesRegex(ScanError,'blocked_address'):resolve_public('example.org',443,1)
 def test_dns_deadline(self):
  def slow(*a,**k):time.sleep(.15);return []
  t=time.monotonic()
  with patch('socket.getaddrinfo',side_effect=slow),self.assertRaisesRegex(ScanError,'dns_timeout'):resolve_public('example.org',443,.02)
  self.assertLess(time.monotonic()-t,.1)
 def test_rebinding(self):
  good=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
  bad=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]
  with patch('socket.getaddrinfo',side_effect=[good,bad]):
   self.assertEqual(resolve_public('example.org',443,1)[4][0],'8.8.8.8')
   with self.assertRaises(ScanError):resolve_public('example.org',443,1)
 def test_ssrf_redirect(self):
  c=Config('https://example.org',check_external_docs=True).validate();t=Transport(c)
  with patch.object(t,'check_robots'),patch.object(t,'one',side_effect=[Response(c.target,302,location='http://127.0.0.1/'),ScanError('blocked_address')]):
   o=t.fetch(c.target,True);self.assertEqual(o.error,'blocked_address')
 def test_peer_mismatch(self):
  entry=(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))
  with patch('socket.socket') as sock:
   sock.return_value.getpeername.return_value=('1.1.1.1',80)
   with self.assertRaisesRegex(ScanError,'peer_mismatch'):PinnedConnection('example.org',80,1,entry).connect()
   sock.return_value.close.assert_called()
 def test_pin_no_second_dns(self):
  entry=(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))
  with patch('socket.socket') as sock,patch('socket.getaddrinfo') as dns:
   sock.return_value.getpeername.return_value=('8.8.8.8',80)
   c=PinnedConnection('example.org',80,1,entry);c.connect()
   sock.return_value.connect.assert_called_once_with(('8.8.8.8',80));dns.assert_not_called()
 def test_scope_query_state(self):
  t=Transport(Config('https://example.org').validate())
  for u in ['https://other.org/','https://example.org/logout','https://example.org/%64elete','https://example.org/?secret=abc']:
   with self.subTest(url=u),self.assertRaises(ScanError):t.allowed(u)
 def test_config_limits(self):
  for key,value in [('max_pages',0),('interval',0),('max_depth',1.5),('max_requests',True),('time_limit',float('nan')),('html_limit',3000000),('check_external_docs','true')]:
   with self.subTest(key=key),self.assertRaises(ScanError):Config('https://example.org',**{key:value}).validate()
 def test_environment_proxy_ignored(self):
  with patch.dict(os.environ,{'HTTPS_PROXY':'http://127.0.0.1:1234'}):
   t=Transport(Config('https://example.org').validate())
   self.assertTrue(t.context.check_hostname)
   self.assertEqual(t.context.verify_mode,2)

class RobotsTests(unittest.TestCase):
 def setUp(self):self.t=Transport(Config('https://example.org').validate())
 def test_denied(self):
  with patch.object(self.t,'one',return_value=Response('',200,b'User-agent: *\nDisallow: /')):
   with self.assertRaisesRegex(ScanError,'robots_denied'):self.t.check_robots('https://example.org/')
 def test_404(self):
  with patch.object(self.t,'one',return_value=Response('',404)):self.t.check_robots('https://example.org/')
 def test_unavailable(self):
  for status in [401,403,429,500,503]:
   t=Transport(Config('https://example.org').validate())
   with patch.object(t,'one',return_value=Response('https://example.org/robots.txt',status)),patch('time.sleep'):
    with self.subTest(status=status),self.assertRaises(ScanError):t.check_robots('https://example.org/')
 def test_cross_origin(self):
  with patch.object(self.t,'one',return_value=Response('',302,location='http://127.0.0.1/')):
   with self.assertRaisesRegex(ScanError,'robots_redirect_scope'):self.t.check_robots('https://example.org/')
 def test_rate_retry(self):
  with patch.object(self.t,'one',return_value=Response('',200)),patch('time.sleep') as sleep:
   self.t.rate_retry(Response('',429,retry_after='5'));sleep.assert_called_once_with(5)
 def test_rate_budget(self):
  with self.assertRaisesRegex(ScanError,'rate_limit_budget'):self.t.rate_retry(Response('',429,retry_after='10000'))
 def test_loop_vs_limit(self):
  with patch.object(self.t,'check_robots'),patch.object(self.t,'one',side_effect=lambda u,l:Response(u,302,location=u)):
   self.assertEqual(self.t.fetch('https://example.org/').error,'redirect_loop')
  t=Transport(Config('https://example.org',max_redirects=1).validate())
  with patch.object(t,'check_robots'),patch.object(t,'one',side_effect=lambda u,l:Response(u,302,location=u+'a')):
   self.assertEqual(t.fetch('https://example.org/').error,'redirect_limit')

class CoreTests(unittest.TestCase):
 def result(self,body='<html>ok</html>',url='https://example.org/',extra=None,**kwargs):
  c=Config(url,**kwargs).validate();routes={url:page(url,body),**(extra or {})};t=FakeTransport(c,routes);return scan(c,transport=t),t
 def test_green(self):
  r,t=self.result();self.assertEqual(r['color'],'green');self.assertEqual(r['scan_status'],'complete');self.assertEqual(len(t.calls),2)
 def test_red(self):
  r,t=self.result('<form><input type=email></form>','http://example.org/');self.assertEqual(r['color'],'red');self.assertEqual(exit_code(r),1)
 def test_document_detected(self):
  url='https://example.org/policy'
  r,t=self.result('<a href="/policy">Политика конфиденциальности</a>',extra={url:page(url,'',404)})
  self.assertTrue(any(f['rule_id']=='C03' for f in r['findings']));self.assertEqual(r['color'],'yellow')
 def test_candidate_not_legal_failure(self):
  r,t=self.result('<a href="/privacy">Privacy</a>',max_depth=0)
  self.assertFalse(r['findings']);self.assertEqual(r['color'],'grey');self.assertGreater(r['coverage']['planned'],r['coverage']['completed'])
 def test_no_policy_not_failure(self):
  r,t=self.result('<html>No docs</html>');self.assertFalse(r['findings'])
 def test_limit(self):
  r,t=self.result('<a href="/a">a</a>',max_pages=1)
  self.assertEqual(r['scan_status'],'partial');self.assertEqual(r['color'],'grey');self.assertEqual(exit_code(r),3)
 def test_no_form_submit(self):
  r,t=self.result('<form action="http://example.org/send"><input type=email></form>')
  self.assertTrue(any(f['rule_id']=='C06' for f in r['findings']));self.assertFalse(any('/send' in u for u in t.calls))
 def test_external_disabled(self):
  r,t=self.result('<a href="https://other.org/policy">Политика конфиденциальности</a>')
  self.assertEqual(len(t.calls),2);self.assertEqual(r['scan_status'],'partial')
 def test_cancel(self):
  c=Config('https://example.org').validate();r=scan(c,transport=FakeTransport(c,{},True))
  self.assertEqual(r['scan_status'],'cancelled');self.assertEqual(exit_code(r),130)
 def test_privacy_and_xss(self):
  r,t=self.result('<form action="/send?token=ULTRASECRET"><input type=password value="ULTRASECRET"><textarea>ULTRASECRET</textarea></form><script>alert(123)</script>')
  # Separate cookie extraction with real header values.
  r['inventory']['cookies']=cookies_inventory([('https://example.org/?key=ULTRASECRET','sessionid=ULTRASECRET; Path=/; HttpOnly; Secure; SameSite=Lax')])
  raw=json.dumps(r);self.assertNotIn('ULTRASECRET',raw);self.assertNotIn('alert(123)',raw)
  r['findings']=[{'rule_id':'<script>alert(1)</script>','fact':'<img src=x onerror=alert(1)>','url':'x','recommendation':'x','reference':'x'}]
  html=render_html(r);self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)
 def test_output_and_overwrite(self):
  r,_=self.result()
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'out';render(r,p)
   self.assertTrue((p/'report.html').is_file())
   with self.assertRaises(ValueError):render(r,p)
   render(r,p,overwrite=True)
   self.assertEqual(json.loads((p/'report.json').read_text())['schema_version'],'1.0')
 def test_symlink_output(self):
  r,_=self.result()
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'out';p.symlink_to(Path(d),target_is_directory=True)
   with self.assertRaises(ValueError):render(r,p)
 def test_cli_no_network_commands(self):
  with patch('pdscan.transport.Transport.one',side_effect=AssertionError('network')),contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(main(['rules','list']),0);self.assertEqual(main(['doctor']),0)
 def test_cli_config_error(self):
  with tempfile.TemporaryDirectory() as d,contextlib.redirect_stderr(io.StringIO()):
   self.assertEqual(main(['scan','ftp://bad','--output',d]),2)
 def test_cli_scan_and_render(self):
  r,_=self.result()
  with tempfile.TemporaryDirectory() as d,patch('pdscan.cli.scan',return_value=r),contextlib.redirect_stdout(io.StringIO()):
   out=Path(d)/'out'
   self.assertEqual(main(['scan','https://example.org','--output',str(out),'--quiet']),0)
   self.assertEqual(main(['render',str(out/'report.json'),'--output',str(out/'copy.html')]),0)
   self.assertTrue((out/'copy.html').exists())

class WireTests(unittest.TestCase):
 """Actual sockets/HTTP, local fixture destination injected only in tests; production forbids it."""
 @classmethod
 def setUpClass(cls):
  class Handler(BaseHTTPRequestHandler):
   def do_GET(self):
    if self.path=='/slow':time.sleep(.5)
    payload=b'<html>hello</html>'
    if self.path=='/large':payload=gzip.compress(b'x'*100000)
    elif self.path=='/gzip':payload=gzip.compress(payload)
    elif self.path=='/broken':payload=b'badgzip'
    self.send_response(200);self.send_header('Content-Type','text/html')
    if self.path in ('/large','/gzip','/broken'):self.send_header('Content-Encoding','gzip')
    self.send_header('Content-Length',str(len(payload)));self.end_headers()
    try:self.wfile.write(payload)
    except OSError:pass
   def log_message(self,*args):pass
  cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
  cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
 def get(self,path,limit=2048,timeout=1):
  entry=(socket.AF_INET,socket.SOCK_STREAM,6,'',self.server.server_address)
  t=Transport(Config('http://example.org/',timeout=timeout).validate())
  with patch('pdscan.transport.resolve_public',return_value=entry),patch('pdscan.transport.public_ip',return_value=True):return t.one('http://example.org'+path,limit)
 def test_real_http(self):self.assertEqual(self.get('/').body,b'<html>hello</html>')
 def test_gzip(self):self.assertEqual(self.get('/gzip').body,b'<html>hello</html>')
 def test_decompression_bomb(self):
  with self.assertRaisesRegex(ScanError,'body_limit'):self.get('/large')
 def test_corrupt_gzip(self):
  with self.assertRaises(ScanError):self.get('/broken')
 def test_request_deadline(self):
  t=time.monotonic()
  with self.assertRaises(ScanError):self.get('/slow',timeout=.1)
  self.assertLess(time.monotonic()-t,.4)
