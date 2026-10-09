"""GET only; no proxies/cookies; DNS checked, IP pinned, peer checked, TLS verified."""
from dataclasses import dataclass, field
import email.utils
import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
import zlib
from urllib.parse import urlsplit, urljoin, unquote
from .robots import RobotsPolicy
from .config import ScanError, normalize_url
from .evidence import now

USER_AGENT = 'PDScan/0.1 (+passive HTTP checks; no form submission)'
REDIRECTS = {301, 302, 303, 307, 308}
TLS_CODES = {9, 10, 18, 19, 20, 21, 62, 64}


def public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return (ip.is_global and not ip.is_multicast and not ip.is_reserved
                and not ip.is_unspecified and not ip.is_loopback and not ip.is_link_local
                and not getattr(ip, 'ipv4_mapped', None)
                and not getattr(ip, 'sixtofour', None) and not getattr(ip, 'teredo', None)
                and ip not in ipaddress.ip_network('64:ff9b::/96')
                and ip not in ipaddress.ip_network('64:ff9b:1::/48'))
    except ValueError:
        return False


def resolve_public(host, port, timeout):
    result = queue.Queue(maxsize=1)
    def run():
        try: result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError: result.put(None)
    threading.Thread(target=run, daemon=True).start()
    try: entries = result.get(timeout=timeout)
    except queue.Empty: raise ScanError('dns_timeout') from None
    if not entries: raise ScanError('dns_error')
    if any(not public_ip(e[4][0]) for e in entries): raise ScanError('blocked_address')
    return entries[0]


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, port, timeout, entry, context=None):
        super().__init__(host, port, timeout=timeout)
        self.entry, self.context = entry, context

    def connect(self):
        family, kind, proto, _, address = self.entry
        raw = socket.socket(family, kind, proto)
        self.sock = raw
        raw.settimeout(self.timeout)
        try:
            raw.connect(address)
            if ipaddress.ip_address(raw.getpeername()[0]) != ipaddress.ip_address(address[0]):
                raise ScanError('peer_mismatch')
            if not public_ip(raw.getpeername()[0]): raise ScanError('blocked_peer')
            if self.context:
                self.sock = self.context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
                self.sock.do_handshake()
                if ipaddress.ip_address(self.sock.getpeername()[0]) != ipaddress.ip_address(address[0]):
                    raise ScanError('peer_mismatch')
        except BaseException:
            raw.close()
            raise


@dataclass
class Hop:
    url: str
    status: int

@dataclass
class Response:
    url: str
    status: int = 0
    body: bytes = b''
    content_type: str = ''
    charset: str = 'utf-8'
    location: str = ''
    cookies: list = field(default_factory=list)
    retry_after: str = ''

@dataclass
class Observation:
    requested: str
    final: str
    status: int = 0
    body: bytes = b''
    content_type: str = ''
    charset: str = 'utf-8'
    chain: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    error: str = ''
    tls_code: int | None = None
    at: str = field(default_factory=now)


class Transport:
    def __init__(self, config):
        self.config = config
        self.started = time.monotonic()
        self.requests = self.bytes = 0
        self.last = {}
        self.robots = {}
        self.blocked_hosts = set()
        self.context = ssl.create_default_context()

    def remaining(self):
        return self.config.time_limit - (time.monotonic() - self.started)

    def budget(self):
        if self.remaining() <= 0: raise ScanError('time_limit')
        if self.requests >= self.config.max_requests: raise ScanError('request_limit')
        if self.bytes >= self.config.byte_limit: raise ScanError('byte_limit')

    def allowed(self, url, external=False):
        p = urlsplit(url)
        if p.hostname not in self.config.hosts and not (external and self.config.check_external_docs):
            raise ScanError('out_of_scope')
        path = unquote(p.path).lower()
        if any(x in path for x in ('logout', 'log-out', 'signout', 'sign-out', 'delete', 'remove', 'unsubscribe', 'отпис', 'удал', 'выход')):
            raise ScanError('state_changing_path')
        if p.query: raise ScanError('query_url_skipped')
        if any(path.startswith(x.lower()) for x in self.config.exclude_paths): raise ScanError('excluded_path')
        if p.hostname in self.blocked_hosts: raise ScanError('host_rate_limited')

    def one(self, url, limit):
        self.active_url = url
        self.budget()
        p = urlsplit(url)
        wait = self.config.interval - (time.monotonic() - self.last.get(p.hostname, 0))
        if wait > 0:
            if wait >= self.remaining(): raise ScanError('time_limit')
            time.sleep(wait)
        timeout = min(self.config.timeout, self.remaining())
        entry = resolve_public(p.hostname, 443 if p.scheme == 'https' else 80, timeout)
        self.budget()
        self.requests += 1
        self.last[p.hostname] = time.monotonic()
        conn = PinnedConnection(p.hostname, 443 if p.scheme == 'https' else 80,
                                min(self.config.timeout, self.remaining()), entry,
                                self.context if p.scheme == 'https' else None)
        expired = threading.Event()
        def abort():
            expired.set()
            if conn.sock:
                try: conn.sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.sock.close()
        timer = threading.Timer(min(self.config.timeout, self.remaining()), abort)
        timer.daemon = True
        timer.start()
        try:
            conn.request('GET', p.path + ('?' + p.query if p.query else ''), headers={
                'User-Agent': USER_AGENT, 'Accept': 'text/html,application/pdf,text/plain;q=0.9,*/*;q=0.1',
                'Accept-Encoding': 'gzip, deflate', 'Connection': 'close'})
            resp = conn.getresponse()
            mime = resp.headers.get_content_type()
            cap = min(limit, self.config.html_limit) if mime in ('text/html', 'application/xhtml+xml') else limit
            encoding = (resp.getheader('Content-Encoding') or 'identity').lower().strip()
            if encoding not in ('gzip', 'deflate', 'identity'): raise ScanError('unsupported_encoding')
            decoder = zlib.decompressobj(16+zlib.MAX_WBITS if encoding == 'gzip' else zlib.MAX_WBITS) if encoding != 'identity' else None
            chunks, decoded, wire = [], 0, 0
            # Redirect bodies are irrelevant, but connection headers count towards limits.
            if resp.status not in REDIRECTS:
                while True:
                    self.budget_bytes()
                    chunk = resp.read(16384)
                    if not chunk: break
                    wire += len(chunk)
                    if wire > cap or wire > self.config.byte_limit-self.bytes: raise ScanError('body_limit')
                    data = decoder.decompress(chunk, cap-decoded+1) if decoder else chunk
                    decoded += len(data)
                    self.bytes += max(len(chunk), len(data))
                    if decoded > cap or self.bytes > self.config.byte_limit: raise ScanError('body_limit')
                    chunks.append(data)
                if decoder and (not decoder.eof or decoder.unused_data): raise ScanError('invalid_compression')
            if expired.is_set(): raise ScanError('request_timeout')
            return Response(url, resp.status, b''.join(chunks), mime,
                            resp.headers.get_content_charset() or 'utf-8', resp.getheader('Location') or '',
                            resp.headers.get_all('Set-Cookie') or [], resp.getheader('Retry-After') or '')
        except ssl.SSLCertVerificationError:
            raise
        except ScanError:
            raise
        except (socket.timeout, TimeoutError):
            raise ScanError('request_timeout') from None
        except (OSError, http.client.HTTPException, zlib.error, ValueError):
            raise ScanError('request_timeout' if expired.is_set() else 'transport_error') from None
        finally:
            timer.cancel()
            conn.close()

    def budget_bytes(self):
        if self.remaining() <= 0: raise ScanError('time_limit')
        if self.bytes >= self.config.byte_limit: raise ScanError('byte_limit')

    def rate_retry(self, resp):
        """Retry once, respecting Retry-After, never beyond the job budget."""
        if resp.status != 429: return resp
        value = resp.retry_after.strip()
        try:
            delay = max(1, int(value))
        except ValueError:
            try: delay = max(1, email.utils.parsedate_to_datetime(value).timestamp()-time.time())
            except (TypeError, ValueError, OverflowError): delay = 1
        if delay >= self.remaining(): raise ScanError('rate_limit_budget')
        time.sleep(delay)
        again = self.one(resp.url, self.config.document_limit)
        if again.status == 429:
            self.blocked_hosts.add(urlsplit(resp.url).hostname)
            raise ScanError('host_rate_limited')
        return again

    def check_robots(self, url):
        p = urlsplit(url)
        origin = p.scheme + '://' + p.netloc
        if origin not in self.robots:
            target = origin + '/robots.txt'
            # robots redirects confined to same origin; no recursive robots fetch.
            seen = set()
            for _ in range(self.config.max_redirects + 1):
                if target in seen: raise ScanError('robots_redirect_loop')
                seen.add(target)
                resp = self.rate_retry(self.one(target, min(self.config.html_limit, 512*1024)))
                if resp.status in REDIRECTS:
                    target = normalize_url(urljoin(target, resp.location))
                    q = urlsplit(target)
                    if q.scheme+'://'+q.netloc != origin: raise ScanError('robots_redirect_scope')
                    self.allowed(target)
                    continue
                if resp.status in (404, 410): self.robots[origin] = None
                elif resp.status == 200:
                    if resp.content_type in ('text/html','application/xhtml+xml'): raise ScanError('robots_html_unexpected')
                    parser = RobotsPolicy(resp.body.decode('utf-8-sig', errors='replace'))
                    self.robots[origin] = parser
                else: raise ScanError('robots_unavailable')
                break
            else: raise ScanError('robots_redirect_limit')
        parser = self.robots[origin]
        if parser:
            if not parser.can_fetch(url): raise ScanError('robots_denied')
            required = parser.delay
            wait = required - (time.monotonic()-self.last.get(p.hostname, 0))
            if wait > 0:
                if wait >= self.remaining(): raise ScanError('robots_delay_budget')
                time.sleep(wait)

    def fetch(self, url, document=False):
        obs = Observation(url, url)
        visited = set()
        current = url
        try:
            for _ in range(self.config.max_redirects+1):
                current = normalize_url(current)
                obs.final = current
                self.allowed(current, external=document)
                if current in visited:
                    obs.error = 'redirect_loop'
                    return obs
                visited.add(current)
                self.check_robots(current)
                resp = self.rate_retry(self.one(current, self.config.document_limit if document else self.config.html_limit))
                obs.chain.append(Hop(current, resp.status))
                obs.cookies.extend((current, v) for v in resp.cookies)
                if resp.status in REDIRECTS:
                    if not resp.location: raise ScanError('redirect_without_location')
                    current = urljoin(current, resp.location)
                    continue
                obs.status, obs.body, obs.content_type, obs.charset = resp.status, resp.body, resp.content_type, resp.charset
                return obs
            raise ScanError('redirect_limit')
        except ssl.SSLCertVerificationError as exc:
            obs.final = getattr(self, 'active_url', current)
            obs.error = 'tls_certificate' if exc.verify_code in TLS_CODES else 'tls_unknown'
            obs.tls_code = exc.verify_code
        except ScanError as exc:
            obs.error = str(exc)
        return obs
