import socket
import ssl
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pdscan.config import Config
from pdscan.robots import RobotsPolicy
from pdscan.transport import Transport

class PolicyTests(unittest.TestCase):
 def test_wildcard(self):
  p=RobotsPolicy('User-agent: *\nDisallow: /private/*\nAllow: /private/open$')
  self.assertFalse(p.can_fetch('https://example.org/private/secret'));self.assertTrue(p.can_fetch('https://example.org/private/open'));self.assertFalse(p.can_fetch('https://example.org/private/open/secret'))
 def test_specific_agent(self):
  p=RobotsPolicy('User-agent: *\nDisallow: /\nUser-agent: PDScan\nAllow: /')
  self.assertTrue(p.can_fetch('https://example.org/a'))
 def test_merge_groups(self):
  p=RobotsPolicy('User-agent: PDScan\nDisallow: /a\nUser-agent: pdscan\nDisallow: /b')
  self.assertFalse(p.can_fetch('https://example.org/a'));self.assertFalse(p.can_fetch('https://example.org/b'))
 def test_percent_encoding(self):
  p=RobotsPolicy('User-agent: *\nDisallow: /private')
  self.assertFalse(p.can_fetch('https://example.org/%70rivate'))
 def test_unicode(self):
  p=RobotsPolicy('User-agent: *\nDisallow: /закрыто')
  self.assertFalse(p.can_fetch('https://example.org/закрыто'))
 def test_delay(self):
  self.assertEqual(RobotsPolicy('User-agent: *\nCrawl-delay: 1.5\nRequest-rate: 1/3').delay,3)
 def test_equal_allow(self):
  self.assertTrue(RobotsPolicy('User-agent: *\nDisallow: /a\nAllow: /a').can_fetch('https://example.org/a'))

class TLSTests(unittest.TestCase):
 def request(self,cert,trust):
  root=Path(__file__).parent/'fixtures'/'tls'
  class Handler(BaseHTTPRequestHandler):
   def do_GET(self):
    self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'OK')
   def log_message(self,*args):pass
  server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/(cert+'.pem'),root/'TEST_ONLY_key.pem')
  server.socket=ctx.wrap_socket(server.socket,server_side=True)
  threading.Thread(target=server.serve_forever,daemon=True).start()
  t=Transport(Config('https://example.org/').validate())
  if trust:t.context=ssl.create_default_context(cafile=str(root/(cert+'.pem')))
  entry=(socket.AF_INET,socket.SOCK_STREAM,6,'',server.server_address)
  try:
   with patch('pdscan.transport.resolve_public',return_value=entry),patch('pdscan.transport.public_ip',return_value=True),patch.object(t,'check_robots'):
    return t.fetch('https://example.org/')
  finally:server.shutdown();server.server_close()
 def test_valid_and_sni(self):
  o=self.request('valid',True);self.assertEqual(o.body,b'OK');self.assertEqual(o.error,'')
 def test_untrusted(self):
  o=self.request('valid',False);self.assertEqual(o.error,'tls_certificate');self.assertEqual(o.body,b'')
 def test_expired(self):
  o=self.request('expired',True);self.assertEqual(o.error,'tls_certificate');self.assertEqual(o.tls_code,10);self.assertEqual(o.body,b'')
 def test_hostname(self):
  o=self.request('wrong_name',True);self.assertEqual(o.error,'tls_certificate');self.assertEqual(o.tls_code,62);self.assertEqual(o.body,b'')
