"""Generate a synthetic report without any network requests."""
import argparse
from pdscan.config import Config
from pdscan.transport import Observation,Hop
from pdscan.core import scan
from pdscan.reporting import render

class DemoTransport:
 def __init__(self):self.requests=0;self.bytes=0
 def remaining(self):return 300
 def allowed(self,*args,**kwargs):pass
 def fetch(self,url,document=False):
  self.requests+=1
  if url.endswith('/policy'):status,body=404,b'Not found'
  else:
   status,body=200,('<html><a href="/policy">Политика конфиденциальности</a><form action="http://example.org/send"><input type=email></form></html>').encode()
  self.bytes+=len(body)
  return Observation(url,url,status,body,'text/html',chain=[Hop(url,status)])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
 r=scan(Config('https://example.org/'),transport=DemoTransport())
 r['limitations'].insert(0,'ДЕМОНСТРАЦИЯ: синтетические ответы. Реальный сайт example.org не обследован.')
 render(r,a.output)
 print(a.output+'/report.html')
