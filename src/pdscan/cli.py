import argparse
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import tomllib
from dataclasses import fields, asdict
from copy import deepcopy
import time
from . import __version__
from .config import Config, ScanError
from .core import scan
from .reporting import render, render_html, prepare_output, write_file
from .rules import RULES
from .legal import legal_fields,browser_fields,reference_text
from .browser_rules import BROWSER_RULES
from .browser import BrowserOptions
from .browser_runner import run_isolated


def parser():
    p=argparse.ArgumentParser(prog='pdscan',description='Поверхностный сканер HTTP/HTML. Не юридическое заключение.')
    p.add_argument('--version',action='version',version=__version__)
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('scan',help='Проверить один публичный сайт')
    s.add_argument('url');s.add_argument('--output',required=True);s.add_argument('--config')
    for name in ('max-pages','max-depth','max-requests','max-redirects'):
        s.add_argument('--'+name,type=int)
    for name in ('time-limit','timeout'):
        s.add_argument('--'+name,type=float)
    s.add_argument('--allow-host',action='append',dest='allow_hosts')
    s.add_argument('--exclude-path',action='append',dest='exclude_paths')
    s.add_argument('--check-external-docs',action='store_true',default=None)
    s.add_argument('--overwrite',action='store_true')
    s.add_argument('--no-color',action='store_true',help='Совместимость: вывод всегда без ANSI-цветов')
    s.add_argument('--quiet',action='store_true')
    s.add_argument('--mode',choices=('r1','combined'),default='r1',help='r1: HTTP; combined: R1 и браузер R2')
    s.add_argument('--browser-pages',type=int,default=1)
    s.add_argument('--browser-wait-ms',type=int,default=1500)
    s.add_argument('--browser-max-requests',type=int,default=300)
    s.add_argument('--browser-time-limit',type=int,default=300)
    s.add_argument('--browser-total-mib',type=int,default=100)
    s.add_argument('--browser-attempt-mib',type=int,default=25)
    s.add_argument('--browser-response-mib',type=int,default=8)
    c=sub.add_parser('compare',help='Сравнить два JSON-отчёта без сети')
    c.add_argument('before');c.add_argument('after');c.add_argument('--output',required=True)

    s.add_argument('--stdout',choices=('json','path'),default='json')
    r=sub.add_parser('render',help='Повторно создать HTML из JSON без сети')
    r.add_argument('report');r.add_argument('--format',choices=['html'],default='html');r.add_argument('--output');r.add_argument('--overwrite',action='store_true')
    sub.add_parser('rules',help='Каталог правил').add_argument('action',choices=['list'])
    d=sub.add_parser('doctor',help='Проверить окружение без сканирования')
    d.add_argument('--output',default='.')
    d.add_argument('--browser',action='store_true',help='Также проверить запуск Chromium без сайта')
    return p


def configuration(args):
    values={}
    if args.config:
        with open(args.config,'rb') as f: root=tomllib.load(f)
        if set(root)!={'scan'} or not isinstance(root['scan'],dict): raise ScanError('config_requires_scan_table')
        values=root['scan']
        allowed={x.name for x in fields(Config)}-{'target'}
        if set(values)-allowed: raise ScanError('unknown_config_key')
    for f in fields(Config):
        value=getattr(args,f.name,None)
        if value is not None: values[f.name]=value
    return Config(target=args.url,**values).validate()


def exit_code(result):
    if result['scan_status']=='cancelled':return 130
    if result['scan_status']!='complete':return 3
    return 1 if result['findings'] else 0


def main(argv=None):
    try:
        args=parser().parse_args(argv)
        if args.command=='rules':
            catalog=[]
            for k,v in {**RULES,**BROWSER_RULES}.items():
                profiles=[browser_fields(k,'not_checked')] if k.startswith('B') else [legal_fields(k,'not_checked',kind) for kind in ('policy','consent','unknown')]
                catalog.append({'id':k,'machine_key':v[0],'name':v[1],'recommendation':v[2],'legal_profiles':profiles})
            print(json.dumps(catalog,ensure_ascii=False,indent=2));return 0
        if args.command=='doctor':
            context=ssl.create_default_context()
            with tempfile.TemporaryFile(dir=args.output) as f:f.write(b'check')
            data={'python':sys.version.split()[0],'platform':sys.platform,'version':__version__,'tls':ssl.OPENSSL_VERSION,'cert_store':context.cert_store_stats(),
                  'output_writable':True,'runtime_dependencies':[], 'proxies':'ignored','supported_platform':sys.platform.startswith('linux')}
            if args.browser:data['browser']=run_isolated(doctor=True)
            print(json.dumps(data,ensure_ascii=False));return 0 if data['supported_platform'] and (not args.browser or data['browser']['ready']) else 2
        if args.command=='render':
            source=Path(args.report)
            if source.stat().st_size>100*1024*1024:raise ValueError('report_too_large')
            result=json.loads(source.read_text(encoding='utf-8'))
            target=Path(args.output) if args.output else source.with_suffix('.html')
            if target.resolve()==source.resolve():raise ValueError('output_is_input')
            if target.exists() and not args.overwrite:raise ValueError('output_exists')
            write_file(target,render_html(result).encode());print(str(target));return 0
        if args.command=='compare':
            from .comparison import compare_reports, comparison_html
            def read(path):
                p=Path(path)
                if p.stat().st_size>100*1024*1024:raise ValueError('report_too_large')
                return json.loads(p.read_text(encoding='utf-8'))
            result=compare_reports(read(args.before),read(args.after))
            output=prepare_output(args.output)
            write_file(output/'comparison.json',json.dumps(result,ensure_ascii=False,indent=2).encode())
            write_file(output/'comparison.html',comparison_html(result).encode())
            print(str(output/'comparison.html'));return 0
        config=configuration(args)
        options=BrowserOptions(args.browser_pages,args.browser_wait_ms,args.browser_max_requests,args.browser_time_limit,total_mib=args.browser_total_mib,attempt_mib=args.browser_attempt_mib,response_mib=args.browser_response_mib).validate()

        output=prepare_output(args.output,args.overwrite)
        # An empty directory is reserved before the first network request.
        progress=None if args.quiet else lambda n,q:print(f'Проверка объекта {n}; в очереди {q}',file=sys.stderr,flush=True)
        start=time.monotonic()
        urls=[]
        result=scan(config,progress=progress,discovered_urls=urls)
        render(result,output,args.overwrite)
        if args.mode=='combined' and result['scan_status']!='cancelled':
            # Keep an independently readable R1 report even if the browser fails.
            render(result,output/'r1',args.overwrite)
            result['r1_summary']={k:deepcopy(result[k]) for k in ('scan_status','color','coverage','metrics')}
            result['scope']['mode']='combined'
            result['browser_options']=asdict(options)
            selected=list(dict.fromkeys(urls or [config.target]))[:options.pages]
            if not args.quiet:print('R1 сохранён. Запуск браузерного этапа R2…',file=sys.stderr,flush=True)
            browser=run_isolated(config,selected,options)
            from .browser_rules import attach_browser
            from .evidence import now
            attach_browser(result,browser,selected)
            result['metrics']['requests']+=browser.get('metrics',{}).get('requests',0)
            result['metrics']['bytes']+=browser.get('metrics',{}).get('bytes',0)
            result['metrics']['elapsed_seconds']=round(time.monotonic()-start,3)
            result['metrics']['browser_counts_available']=bool(browser.get('metrics'))
            result['finished_at']=now()
            render(result,output,True)

        summary={k:result[k] for k in ('scan_id','scan_status','color','coverage','metrics')}
        summary['report']=str(output/'report.html')
        summary['checks']=[{k:c.get(k) for k in ('rule_id','url','outcome','message','reference','legal_status')} for c in result['checks']]
        print(str(output/'report.html') if args.stdout=='path' else json.dumps(summary,ensure_ascii=False))
        return exit_code(result)
    except KeyboardInterrupt:
        print('Отмена до запуска либо во время сохранения; проверьте наличие report.json.',file=sys.stderr);return 130
    except (ScanError,ValueError,TypeError,KeyError,OSError,ssl.SSLError) as exc:
        # Avoid printing arbitrary exception text, URLs, paths or secrets.
        code=str(exc) if isinstance(exc,ScanError) else type(exc).__name__
        print('Ошибка: '+code+'. Проверьте параметры, окружение и каталог результата.',file=sys.stderr);return 2
