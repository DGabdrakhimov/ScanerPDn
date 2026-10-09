import argparse
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import tomllib
from dataclasses import fields
from . import __version__
from .config import Config, ScanError
from .core import scan
from .reporting import render, render_html, prepare_output, write_file
from .rules import RULES, REFERENCE


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
    s.add_argument('--stdout',choices=('json','path'),default='json')
    r=sub.add_parser('render',help='Повторно создать HTML из JSON без сети')
    r.add_argument('report');r.add_argument('--format',choices=['html'],default='html');r.add_argument('--output');r.add_argument('--overwrite',action='store_true')
    sub.add_parser('rules',help='Каталог правил').add_argument('action',choices=['list'])
    d=sub.add_parser('doctor',help='Проверить окружение без сканирования')
    d.add_argument('--output',default='.')
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
            print(json.dumps([{'id':k,'machine_key':v[0],'name':v[1],'recommendation':v[2],'reference':REFERENCE,'revision':1} for k,v in RULES.items()],ensure_ascii=False,indent=2));return 0
        if args.command=='doctor':
            context=ssl.create_default_context()
            with tempfile.TemporaryFile(dir=args.output) as f:f.write(b'check')
            data={'python':sys.version.split()[0],'platform':sys.platform,'version':__version__,'tls':ssl.OPENSSL_VERSION,'cert_store':context.cert_store_stats(),
                  'output_writable':True,'runtime_dependencies':[], 'proxies':'ignored','supported_platform':sys.platform.startswith('linux')}
            print(json.dumps(data,ensure_ascii=False));return 0 if data['supported_platform'] else 2
        if args.command=='render':
            source=Path(args.report)
            if source.stat().st_size>100*1024*1024:raise ValueError('report_too_large')
            result=json.loads(source.read_text(encoding='utf-8'))
            target=Path(args.output) if args.output else source.with_suffix('.html')
            if target.resolve()==source.resolve():raise ValueError('output_is_input')
            if target.exists() and not args.overwrite:raise ValueError('output_exists')
            write_file(target,render_html(result).encode());print(str(target));return 0
        config=configuration(args)
        output=prepare_output(args.output,args.overwrite)
        # An empty directory is reserved before the first network request.
        progress=None if args.quiet else lambda n,q:print(f'Проверка объекта {n}; в очереди {q}',file=sys.stderr,flush=True)
        result=scan(config,progress=progress)
        render(result,output,args.overwrite)
        summary={k:result[k] for k in ('scan_id','scan_status','color','coverage','metrics')}
        summary['report']=str(output/'report.html')
        print(str(output/'report.html') if args.stdout=='path' else json.dumps(summary,ensure_ascii=False))
        return exit_code(result)
    except KeyboardInterrupt:
        print('Отмена до запуска либо во время сохранения; проверьте наличие report.json.',file=sys.stderr);return 130
    except (ScanError,ValueError,TypeError,KeyError,OSError,ssl.SSLError) as exc:
        # Avoid printing arbitrary exception text, URLs, paths or secrets.
        code=str(exc) if isinstance(exc,ScanError) else type(exc).__name__
        print('Ошибка: '+code+'. Проверьте параметры, окружение и каталог результата.',file=sys.stderr);return 2
