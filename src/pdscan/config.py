from dataclasses import dataclass, asdict
from urllib.parse import urlsplit, urlunsplit, quote
import ipaddress
import re

class ScanError(Exception):
    """Only fixed reason codes may be logged; never log raw exception strings."""


def normalize_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 4096 or re.search(r'[\x00-\x20\x7f\\]', url):
        raise ScanError('invalid_url')
    try:
        p = urlsplit(url)
        if p.scheme.lower() not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        host = p.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        if '%' in host: raise ValueError()
        try:
            addr = ipaddress.ip_address(host)
            host = addr.compressed
        except ValueError:
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host): raise ValueError()
            if re.fullmatch(r'[0-9.]+', host) or host.startswith('0x'): raise ValueError()
            if any(len(x) > 63 or not x or x.startswith('-') or x.endswith('-') for x in host.split('.')): raise ValueError()
        port = p.port or (443 if p.scheme.lower() == 'https' else 80)
        if port != (443 if p.scheme.lower() == 'https' else 80): raise ValueError()
        authority = '[' + host + ']' if ':' in host else host
        path = quote(p.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(p.query, safe="%:@!$&'()*+,;=/?-._~")
        return urlunsplit((p.scheme.lower(), authority, path, query, ''))
    except (ValueError, UnicodeError):
        raise ScanError('invalid_url') from None


@dataclass
class Config:
    target: str
    max_pages: int = 30
    max_depth: int = 2
    max_requests: int = 100
    time_limit: float = 300
    timeout: float = 10
    max_redirects: int = 5
    html_limit: int = 2 * 1024 * 1024
    document_limit: int = 5 * 1024 * 1024
    byte_limit: int = 25 * 1024 * 1024
    interval: float = 1.0
    allow_hosts: tuple = ()
    exclude_paths: tuple = ()
    check_external_docs: bool = False

    def validate(self):
        self.target = normalize_url(self.target)
        bounds = {'max_pages': (1, 300), 'max_depth': (0, 5), 'max_requests': (2, 1000),
                  'time_limit': (1, 1800), 'timeout': (0.1, 30), 'max_redirects': (0, 10),
                  'html_limit': (1024, 2*1024*1024), 'document_limit': (1024, 5*1024*1024),
                  'byte_limit': (1024, 100*1024*1024), 'interval': (1, 60)}
        for key, (low, high) in bounds.items():
            value = getattr(self, key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise ScanError('invalid_config_' + key)
            if key not in ('time_limit', 'timeout', 'interval') and not isinstance(value, int):
                raise ScanError('invalid_config_' + key)
        if type(self.check_external_docs) is not bool: raise ScanError('invalid_config_external_docs')
        if not isinstance(self.allow_hosts, (list, tuple)) or not isinstance(self.exclude_paths, (list, tuple)):
            raise ScanError('invalid_config_lists')
        hosts = []
        for h in self.allow_hosts:
            if not isinstance(h, str) or any(c in h for c in '/:@?#'): raise ScanError('invalid_allow_host')
            hosts.append(urlsplit(normalize_url('https://' + h)).hostname)
        if not all(isinstance(x, str) and x.startswith('/') and len(x) <= 512 for x in self.exclude_paths):
            raise ScanError('invalid_exclude_path')
        self.allow_hosts = tuple(hosts)
        return self

    @property
    def hosts(self):
        return {urlsplit(self.target).hostname, *self.allow_hosts}

    def public_dict(self):
        from .evidence import safe_url, token
        d = asdict(self)
        d['target'] = safe_url(self.target)
        d['exclude_paths'] = [token(x) for x in self.exclude_paths]
        return d
