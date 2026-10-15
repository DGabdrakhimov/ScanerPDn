"""Optional browser adapter. All HTTP is fulfilled through the pinned R1 transport.
No route.continue/fetch; direct browser egress uses a deliberately dead proxy.
"""
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import time
from .config import Config,ScanError,normalize_url
from .transport import Transport,REDIRECTS
from .evidence import safe_url,token,artifact,now

SCENARIOS={'S0':'До выбора','S1':'После отказа','S2':'После согласия','S3':'После отзыва'}
@dataclass
class BrowserOptions:
 pages:int=1
 wait_ms:int=1500
 max_requests:int=300
 time_limit:int=300
 executable:str|None=None
 total_mib:int=100
 attempt_mib:int=25
 response_mib:int=8
 def validate(self):
  if not 1<=self.pages<=5 or not 100<=self.wait_ms<=5000 or not 8<=self.max_requests<=1000 or not 10<=self.time_limit<=1800:raise ScanError('invalid_browser_options')
  if any(type(x) is not int for x in (self.total_mib,self.attempt_mib,self.response_mib)) or not 1<=self.response_mib<=32 or not 1<=self.attempt_mib<=100 or not 1<=self.total_mib<=100 or self.response_mib>self.attempt_mib or self.attempt_mib>self.total_mib:raise ScanError('invalid_browser_byte_options')
  return self

# Only an unambiguous button in an explicitly cookie-related container is eligible.
# No navigation links, form buttons, general "OK", or arbitrary user selectors.
BUTTON_JS=Path(__file__).with_name('consent_actions.js').read_text(encoding='utf-8')
INIT=r'''(() => {
 document.addEventListener('submit', e=>{e.preventDefault();e.stopImmediatePropagation()},true);
 HTMLFormElement.prototype.submit=function(){throw new Error('PDScan: form blocked')};
 HTMLFormElement.prototype.requestSubmit=function(){throw new Error('PDScan: form blocked')};
 for(const name of ['Worker','SharedWorker','RTCPeerConnection','webkitRTCPeerConnection'])try{Object.defineProperty(window,name,{value:class{constructor(){throw new Error('PDScan: unavailable')}},writable:false,configurable:false})}catch{}
})()'''

def sanitized_snapshot(raw):
 out={'controls':[],'documents':[],'storage':[token(x) for x in raw.get('storage',[])], 'limited':bool(raw.get('limited')), 'frames':int(raw.get('frames',0))}
 for c in raw.get('controls',[])[:200]:
  out['controls'].append({k:c.get(k) for k in ('index','kind','visible','disabled','checked','initial_checked','association','consent','marketing','combined','negative')}|{'label_hash':token(c.get('label','')),'links':[{'url':safe_url(x['url']),'label_hash':token(x.get('label',''))} for x in c.get('links',[])[:20]]})
 for d in raw.get('documents',[])[:100]:out['documents'].append({'url':safe_url(d['url']),'type':d['type'],'label_hash':token(d.get('label',''))})
 return out

def cookie_metadata(items):
 return [{'name':token(x['name']),'domain':token(x.get('domain','')),'path':token(x.get('path','')),'secure':bool(x.get('secure')),'httponly':bool(x.get('httpOnly')),'samesite':x.get('sameSite'),'expires':x.get('expires')} for x in items[:200]]

class Gateway:
 def __init__(self,config,options):
  self.client=Transport(Config(config.target,max_requests=options.max_requests,time_limit=options.time_limit,timeout=config.timeout,allow_hosts=config.allow_hosts,exclude_paths=config.exclude_paths,byte_limit=options.total_mib*1024*1024).validate())
  self.options=options
  self.total_limit=options.total_mib*1024*1024
  self.attempt_start=0
  self.total_events=0
  self.truncated=False
 def start_attempt(self):
  self.attempt_start=self.client.bytes
  self.truncated=False
 def stop_reason(self):
  if self.client.remaining()<=0:return 'time_limit'
  if self.client.requests>=self.client.config.max_requests:return 'request_limit'
  if self.client.bytes>=self.total_limit:return 'browser_total_byte_limit'
  return None
 def handle(self,route,page,events,phase):
  request=route.request
  event={'url':safe_url(request.url),'method':request.method if request.method in ('GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH') else 'other','resource_type':request.resource_type,'phase':phase[0],'delivery':'blocked','reason':''}
  self.total_events+=1
  try:
   if self.total_events>2000:raise ScanError('browser_event_limit')
   if request.method!='GET':raise ScanError('browser_method_blocked')
   url=normalize_url(request.url)
   if request.is_navigation_request() and (request.frame!=page.main_frame or phase[0]!='load'):raise ScanError('browser_navigation_blocked')
   self.client.allowed(url)
   attempt_cap=self.attempt_start+self.options.attempt_mib*1024*1024
   self.client.config.byte_limit=min(self.total_limit,attempt_cap)
   try:
    self.client.check_robots(url)
    response=self.client.one(url,self.options.response_mib*1024*1024)
   except ScanError as exc:
    code=str(exc)
    if code=='byte_limit':code='browser_attempt_byte_limit' if attempt_cap<self.total_limit else 'browser_total_byte_limit'
    elif code=='body_limit':code='browser_response_size_limit'
    raise ScanError(code) from None
   finally:self.client.config.byte_limit=self.total_limit
   # Request cookies are deliberately not forwarded; no authenticated browsing.
   # Response cookies are installed by Chromium from the fulfilled response.
   headers={'content-type':response.content_type+'; charset='+response.charset}
   if response.location:headers['location']=response.location
   if response.cookies:headers['set-cookie']='\n'.join(response.cookies)
   event['status']=response.status
   route.fulfill(status=response.status,headers=headers,body=response.body)
   event['delivery']='received';event['reason']=''
  except ScanError as exc:
   event['reason']=str(exc);route.abort('blockedbyclient')
  except Exception:
   event['reason']='browser_gateway_error'
   try:route.abort('failed')
   except Exception:pass
  finally:
   if len(events)<500:events.append(event)
   else:self.truncated=True

def run_browser(config,urls,options,*,gateway=None):
 options.validate()
 result={'status':'partial','started_at':now(),'finished_at':None,'adapter':'playwright','scenarios':[],'limitations':['Браузер получает только GET без query в разрешённой области; POST, формы, внешние хосты, workers, WebSocket и фоновые каналы заблокированы.','Cookie запросов не пересылаются серверу. Сценарии зависящих от серверной сессии сайтов могут быть неполными.','Заголовки ответа воспроизводятся частично (тип, переходы, cookie); это ограниченный инструментальный контекст, не точная копия пользовательского браузера.','Тексты, значения полей, cookie и localStorage не сохраняются; снимок содержит структуру и признаки. Закрытые shadow DOM и iframe не анализируются.'],'error':None,'metrics':{},'limits':{'total_mib':options.total_mib,'attempt_mib':options.attempt_mib,'response_mib':options.response_mib,'html_mib':min(2,options.response_mib),'max_requests':options.max_requests,'time_limit':options.time_limit}}
 result['scenarios']=[new_entry(url,s,a) for url in list(dict.fromkeys(urls))[:options.pages] for s in SCENARIOS for a in (1,2)]
 try:
  from playwright.sync_api import sync_playwright
  from importlib.metadata import version
  result["playwright_version"]=version("playwright")
 except ImportError:
  result['error']='playwright_not_installed';result['finished_at']=now();return finalize(result)
 gate=gateway or Gateway(config,options)
 probe=Path(__file__).with_name('browser_probe.js').read_text()
 try:
  with sync_playwright() as pw:
   args=['--disable-background-networking','--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--proxy-bypass-list=<-loopback>']
   browser=pw.chromium.launch(headless=True,executable_path=options.executable,args=args,proxy={'server':'http://127.0.0.1:9','bypass':''})
   result['chromium_version']=browser.version
   try:
    for url in list(dict.fromkeys(urls))[:options.pages]:
     for scenario in SCENARIOS:
      for attempt in (1,2):
       entry=next(e for e in result['scenarios'] if e['url']==safe_url(url) and e['scenario']==scenario and e['attempt']==attempt)
       reason=gate.stop_reason()
       if reason:entry['error']=reason;continue
       gate.start_attempt()
       entry['status']='partial';entry['stage']='load'
       start_bytes,start_requests=gate.client.bytes,gate.client.requests
       context=browser.new_context(service_workers='block',accept_downloads=False,ignore_https_errors=False,permissions=[])
       try:
        context.set_default_timeout(min(10000,max(100,gate.client.remaining()*1000)))
        context.add_init_script(INIT)
        context.route_web_socket('**/*',lambda ws:ws.close())
        page=context.new_page();page.on('dialog',lambda dialog:dialog.dismiss())
        phase=['load']
        context.route('**/*',lambda route:gate.handle(route,page,entry['events'],phase))
        page.goto(url,wait_until='domcontentloaded',timeout=min(30000,max(100,gate.client.remaining()*1000)))
        page.wait_for_timeout(options.wait_ms)
        entry['before']=sanitized_snapshot(page.evaluate(probe))
        entry['diagnostics']=sanitize_diagnostics(page.evaluate(BUTTON_JS,{'action':None,'click':False}))
        entry['stage']='observe'
        phase[0]='observe'
        actions={'S0':[],'S1':['reject'],'S2':['accept'],'S3':['accept','revoke']}[scenario]
        supported=True
        for action in actions:
         phase[0]=action
         entry['stage']=action
         click=sanitize_diagnostics(page.evaluate(BUTTON_JS,{'action':action,'click':True}));entry['actions'].append({'action':action,**click})
         if click['status']!='clicked':supported=False;break
         page.wait_for_timeout(options.wait_ms)
         entry['checkpoints'][action]={'snapshot':sanitized_snapshot(page.evaluate(probe)),'cookies':cookie_metadata(context.cookies())}
        entry['snapshot']=sanitized_snapshot(page.evaluate(probe))
        entry['cookies']=cookie_metadata(context.cookies())
        entry['status']='complete' if supported and not gate.truncated and not entry.get('diagnostics',{}).get('limited') and not entry['snapshot']['limited'] and not entry['snapshot']['frames'] and all(e['delivery']=='received' for e in entry['events']) else 'unsupported' if not supported else 'partial'
       except Exception:entry['error']='browser_scenario_error'
       finally:
        entry['events_truncated']=gate.truncated
        entry['metrics']={'bytes':gate.client.bytes-start_bytes,'requests':gate.client.requests-start_requests}
        context.close()
   finally:browser.close()
 except KeyboardInterrupt:result['error']='cancelled'
 except Exception:result['error']='browser_launch_or_runtime_error'
 result['status']='complete' if result['scenarios'] and all(x['status']=='complete' for x in result['scenarios']) else 'partial'
 result['metrics']={'requests':gate.client.requests,'bytes':gate.client.bytes}
 result['finished_at']=now()
 return finalize(result)

ACTIONS={'S0':[],'S1':['reject'],'S2':['accept'],'S3':['accept','revoke']}
def new_entry(url,scenario,attempt):
 return {'url':safe_url(url),'scenario':scenario,'attempt':attempt,'status':'not_started','stage':'not_started','events':[],'actions':[],'snapshot':{},'cookies':[],'before':{},'checkpoints':{},'error':None,'diagnostics':{}}

def sanitize_diagnostics(raw):
 out={k:raw.get(k) for k in ('status','count','reason','limited')}
 out['candidates']=[{k:v for k,v in c.items() if k!='label'}|{'label_hash':token(c.get('label',''))} for c in raw.get('candidates',[])[:200]]
 return out

def finalize(result):
 for e in result['scenarios']:
  if e['status']=='not_started' and not e.get('error'):e['error']=result.get('error') or 'browser_not_started'
  reasons=[]
  if e.get('error'):reasons.append(e['error'])
  reasons.extend(x['reason'] for x in e.get('events',[]) if x.get('reason'))
  reasons.extend(a.get('reason') or 'no_eligible_button' for a in e.get('actions',[]) if a['status']!='clicked')
  if e.get('snapshot',{}).get('limited') or e.get('diagnostics',{}).get('limited'):reasons.append('diagnostic_limit')
  if e.get('events_truncated'):reasons.append('browser_event_limit')
  if e.get('snapshot',{}).get('frames'):reasons.append('frames_not_inspected')
  if e['status']!='complete' and not reasons:reasons.append('browser_observation_incomplete')
  e['reasons']=list(dict.fromkeys(reasons))
  done={a['action'] for a in e.get('actions',[]) if a['status']=='clicked'}
  e['not_performed']=[] if e.get('actions_status_unknown') else [a for a in ACTIONS[e['scenario']] if a not in done]
 return result
