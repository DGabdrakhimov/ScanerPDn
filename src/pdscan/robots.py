"""Robots policy: most specific user-agent, wildcard/end anchor, longest path wins."""
import re
from urllib.parse import quote, urlsplit
from .config import ScanError


def canonical_path(s):
    s=quote(s,safe='/%*?$=&:@!+,;~-._')
    def repl(m):
        c=chr(int(m.group(1),16))
        return c if c.isascii() and (c.isalnum() or c in '-._~') else '%'+m.group(1).upper()
    return re.sub(r'%([0-9a-fA-F]{2})',repl,s)


class RobotsPolicy:
    def __init__(self,text):
        groups=[];agents=[];rules=[];delays=[];rates=[];has_rules=False
        for line in text.splitlines()+['User-agent: __end__']:
            line=line.split('#',1)[0].strip()
            if ':' not in line:continue
            key,value=(s.strip() for s in line.split(':',1));key=key.lower()
            if key=='user-agent':
                if has_rules:
                    groups.append((agents,rules,delays,rates));agents=[];rules=[];delays=[];rates=[];has_rules=False
                agents.append(value.lower())
            elif agents:
                has_rules=True
                if key in ('allow','disallow') and value:rules.append((key,canonical_path(value)))
                elif key=='crawl-delay':
                    try:
                        v=float(value)
                        if 0<v<86400:delays.append(v)
                    except ValueError:pass
                elif key=='request-rate':
                    try:
                        n,s=map(int,value.split('/'))
                        if n>0 and s>0:rates.append(s/n)
                    except ValueError:pass
        scored=[(max((len(a) if a!='*' else 0 for a in aa if a=='*' or a in 'pdscan'),default=-1),r,d,rr) for aa,r,d,rr in groups]
        best=max((x[0] for x in scored),default=-1)
        selected=[x for x in scored if x[0]==best and best>=0]
        self.rules=[rule for _,rules,_,_ in selected for rule in rules]
        if len(self.rules)>2000 or any(len(p)>4096 for _,p in self.rules): raise ScanError('robots_rule_limit')
        self.delay=max([0]+[v for _,_,d,r in selected for v in d+r])

    def can_fetch(self,url):
        p=urlsplit(url);target=canonical_path(p.path+('?' + p.query if p.query else ''))
        matches=[]
        for kind,pattern in self.rules:
            anchor=pattern.endswith('$');pattern=pattern[:-1] if anchor else pattern
            if wildcard_match(pattern,target,anchor):matches.append((len(pattern.replace('*','')),kind=='allow'))
        return max(matches,default=(0,True))[1]


def wildcard_match(pattern, target, end):
    # Literal segments, no regex backtracking from untrusted robots patterns.
    parts=pattern.split('*')
    if not target.startswith(parts[0]): return False
    pos=len(parts[0])
    if len(parts)==1: return not end or pos==len(target)
    for segment in parts[1:-1]:
        found=target.find(segment,pos)
        if found<0: return False
        pos=found+len(segment)
    last=parts[-1]
    if end: return target.endswith(last) and len(target)-len(last)>=pos
    return target.find(last,pos)>=0
