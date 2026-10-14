"""Isolate Chromium and enforce a wall-clock deadline, including hung JavaScript."""
import multiprocessing
import os
import signal
from .evidence import now

def failed(reason):
    return {'status':'partial','started_at':now(),'finished_at':now(),'adapter':'playwright',
            'scenarios':[],'error':reason,'metrics':{},
            'limitations':['Браузерный этап не завершён; наблюдения этого этапа недоступны. HTTP-результат R1 сохранён.']}

def worker(pipe,config,urls,options,doctor):
    if hasattr(os,'setsid'): os.setsid()
    try:
        if doctor:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True)
                browser.close()
            result={'ready':True,'error':None}
        else:
            from .browser import run_browser
            result=run_browser(config,urls,options)
        pipe.send(result)
    except ImportError: pipe.send({'ready':False,'error':'playwright_not_installed'} if doctor else failed('playwright_not_installed'))
    except Exception: pipe.send({'ready':False,'error':'browser_launch_or_runtime_error'} if doctor else failed('browser_launch_or_runtime_error'))
    finally: pipe.close()

def run_isolated(config=None,urls=(),options=None,*,doctor=False):
    ctx=multiprocessing.get_context('spawn')
    reader,writer=ctx.Pipe(duplex=False)
    process=ctx.Process(target=worker,args=(writer,config,urls,options,doctor))
    process.start();writer.close()
    try:
        if reader.poll(30 if doctor else options.time_limit+30):
            try:return reader.recv()
            except EOFError:reason='browser_worker_failed'
        else: reason='browser_timeout'
        return {'ready':False,'error':reason} if doctor else failed(reason)
    except KeyboardInterrupt:
        return {'ready':False,'error':'cancelled'} if doctor else failed('cancelled')
    finally:
        # Child establishes its own process group; only kill that group, never ours.
        if hasattr(os,'killpg'):
            try:
                if os.getpgid(process.pid)==process.pid: os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError: pass
        if process.is_alive():process.terminate()
        process.join(timeout=3)
        if process.is_alive():process.kill();process.join(timeout=3)
        reader.close()
