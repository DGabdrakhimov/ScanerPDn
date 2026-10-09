"""175 explicit rule examples: 10 positive, 10 negative, 5 edge per rule.
Synthetic coverage is not a statistical claim about real websites.
"""
import unittest
from copy import deepcopy
from pdscan.rules import evaluate
from pdscan.transport import Observation, Hop


def obs(url='https://example.org/', body='<html><body>ok</body></html>', status=200, mime='text/html', error='', code=None):
    return Observation(url,url,status,body.encode(),mime,chain=[Hop(url,status)],error=error,tls_code=code)


def redirect(start='https://example.org/policy', end='http://example.org/policy', status=200):
    o=obs(end,status=status);o.requested=start;o.chain=[Hop(start,302),Hop(end,status)];return o


def case(o,expected='fail',doc=False,second=None):return o,second or deepcopy(o),doc,expected


DATA={}
# C01: actual form variants, not simply the same case with different URL counters.
http_bodies=['<html>ok</html>','<form><input type=email></form>','<form><input type=tel></form>',
 '<form><input type=password></form>','<FORM><INPUT TYPE=EMAIL></FORM>',
 '<form id=f></form><input form=f type=email>','<form><input type=text></form>',
 '<form><input type=hidden value=secret></form>','<form><textarea>secret</textarea></form>',
 '<form action=https://example.org/><input type=email></form>']
DATA['C01']=[case(obs('http://example.org/',b)) for b in http_bodies]+[
 case(obs(body=b),'pass') for b in http_bodies]+[
 case(obs(error='dns_error'),'inconclusive'),case(obs(status=403),'inconclusive'),
 case(obs('http://example.org/'), 'inconclusive', second=obs()),
 case(obs('http://example.org/','<form><form><input type=email>'),'inconclusive'),
 case(obs(mime='application/pdf'),'inconclusive')]
# C02: certificate codes and host contexts.
DATA['C02']=[case(obs(url=u,error='tls_certificate',code=c)) for u,c in [
 ('https://example.org/',9),('https://example.org/',10),('https://example.org/',18),
 ('https://example.org/',19),('https://example.org/',20),('https://example.org/',21),
 ('https://example.org/',62),('https://example.org/',64),('https://www.example.org/',10),('https://93.184.215.14/',64)]]+[
 case(obs(status=s),'pass') for s in [200,201,204,301,302,400,401,403,404,500]]+[
 case(obs(error='tls_unknown',code=1),'inconclusive'),case(obs(error='dns_error'),'inconclusive'),
 case(obs(error='request_timeout'),'inconclusive'),case(obs(error='tls_certificate',code=10),'inconclusive',second=obs()),
 case(obs(error='tls_certificate',code=10),'inconclusive',second=obs(error='tls_certificate',code=62))]
# C03: 404 and 410 final status, including redirected document endpoints.
c03=[]
for s in (404,410):
 for mime in ('text/html','text/plain','application/pdf','application/octet-stream'):
  c03.append(case(obs(status=s,mime=mime),doc=True))
 c03.append(case(redirect(status=s),doc=True))
DATA['C03']=c03+[
 case(obs(body=b,mime=m),'pass',True) for b,m in [('ok','text/plain'),('<html>policy</html>','text/html'),('%PDF-1.7','application/pdf'),('','text/html'),('<div id=app></div>','text/html')]]+[
 case(obs(status=s),'not_applicable',False) for s in (404,410,200,403,500)]+[
 case(obs(status=s),'inconclusive',True) for s in (403,429,500,204)]+[
 case(obs(status=404),'inconclusive',True,obs(status=410))]
# C04: ten different actual cycle paths/status chains.
c04=[]
for n,statuses in enumerate([(301,301),(302,302),(303,303),(307,307),(308,308),(301,302),(302,307),(301,308,302),(302,303,307),(308,307,301,302)]):
 o=obs(error='redirect_loop');o.chain=[Hop('https://example.org/'+chr(97+i),s) for i,s in enumerate(statuses)];o.final=o.chain[0].url;c04.append(case(o,doc=True))
DATA['C04']=c04+[
 case(redirect(status=s),'pass',True) for s in (200,201,204,400,404)]+[
 case(obs(error=e),'not_applicable',False) for e in ('redirect_loop','redirect_limit','dns_error','robots_denied','')]+[
 case(obs(error=e),'inconclusive',True) for e in ('redirect_limit','robots_denied','transport_error','request_limit')]+[
 case(c04[0][0],'inconclusive',True,c04[1][0])]
# C05: distinct redirect status and path patterns.
c05=[]
for code in (301,302,303,307,308):
 o=redirect();o.chain[0].status=code;c05.append(case(o,doc=True))
 o=redirect();o.chain=[Hop('https://example.org/policy',code),Hop('https://example.org/legal',302),Hop('http://example.org/legal',200)];o.final=o.chain[-1].url;c05.append(case(o,doc=True))
DATA['C05']=c05+[
 case(redirect(start=a,end=b),'pass',True) for a,b in [('https://example.org/a','https://example.org/b'),('http://example.org/a','https://example.org/b'),('http://example.org/a','http://example.org/b'),('https://example.org/a','https://www.example.org/b'),('https://example.org/a','https://example.org/a')]]+[
 case(c05[i][0],'not_applicable',False) for i in range(5)]+[
 case(obs(error=e),'inconclusive',True) for e in ('redirect_limit','out_of_scope','blocked_address','robots_denied')]+[
 case(redirect(),'inconclusive',True,obs())]
# C06: action, base URL, overrides and explicit form ownership.
forms=[
 '<form action="http://example.org/send"><input type=email></form>',
 '<form action="http://example.org/send"><input type=tel></form>',
 '<form action="http://example.org/send"><input type=password></form>',
 '<base href="http://example.org/"><form action="send"><input type=email></form>',
 '<form action="https://example.org/send"><input type=email><button formaction="http://example.org/send">Send</button></form>',
 '<form><input type=email><input type=submit formaction="http://example.org/send"></form>',
 '<form><input type=email><input type=image formaction="http://example.org/send"></form>',
 '<form id=f action="http://example.org/send"></form><input form=f type=email>',
 '<form id=f><input type=email></form><button form=f formaction="http://example.org/send">Send</button>',
 '<FORM ACTION="http://example.org/send"><INPUT TYPE=EMAIL></FORM>']
DATA['C06']=[case(obs(body=b)) for b in forms]+[
 case(obs(body=b),'pass') for b in [
 '<form action="https://example.org/send"><input type=email></form>',
 '<form action="/send"><input type=email></form>',
 '<form action="//example.org/send"><input type=email></form>',
 '<form><input type=email></form>',
 '<form action=""><input type=email></form>',
 '<form><input type=email><button type=button formaction="http://example.org/">X</button></form>']]+[
 case(obs(body=b),'not_applicable') for b in ['<form action="http://example.org/"><input type=text></form>',
 '<input type=email>','<form method=dialog action="http://example.org/"><input type=email></form>',
 '<template><form action="http://example.org/"><input type=email></form></template>']]+[
 case(obs(error='request_timeout'),'inconclusive'),case(obs(body='<form><form><input type=email>'),'inconclusive'),
 case(obs(body=forms[0]),'inconclusive',second=obs(body=forms[0].replace('http:','https:'))),
 case(obs(status=403),'inconclusive'),case(obs(mime='application/pdf'),'inconclusive')]
# C07: supported MIME, status and non-empty content.
DATA['C07']=[case(obs(url=u,body='',mime=m),doc=True) for u,m in [
 ('https://example.org/policy','text/html'),('https://example.org/policy','text/plain'),('https://example.org/policy','application/pdf'),('https://example.org/policy','application/xhtml+xml'),
 ('http://example.org/policy','text/html'),('http://example.org/policy','text/plain'),('http://example.org/policy','application/pdf'),('http://example.org/policy','application/xhtml+xml'),
 ('https://www.example.org/consent','text/html'),('https://example.org/legal','application/pdf')]]+[
 case(obs(body=b),'pass',True) for b in [' ','\n','<html></html>','<div id=app></div>','%PDF-1.7','{}','0','policy','<script>1</script>','\x00']]+[
 case(obs(body='',status=204),'inconclusive',True),case(obs(body='',mime='application/octet-stream'),'inconclusive',True),
 case(obs(error='body_limit'),'inconclusive',True),case(obs(body=''),'inconclusive',True,obs(body='policy')),
 case(obs(body='',status=403),'inconclusive',True)]


class RulesTests(unittest.TestCase): pass

def make(rule,item):
 def test(self):
  a,b,doc,expected=item
  self.assertEqual(evaluate(rule,a,b,doc)[0],expected)
 return test
for rule,items in DATA.items():
 assert len(items)==25,(rule,len(items))
 for i,item in enumerate(items):setattr(RulesTests,f'test_{rule}_{i+1:02}',make(rule,item))
