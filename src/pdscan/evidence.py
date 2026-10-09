import hashlib
import json
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime, timezone

SAFE_SEGMENTS = {'privacy', 'policy', 'personal-data', 'consent', 'contacts', 'contact', 'index.html', 'index.php', 'robots.txt', 'about', 'legal', 'ru', 'en'}
SAFE_NAMES = {'email', 'phone', 'tel', 'password', 'name', 'firstname', 'lastname', 'message', 'csrf', 'sessionid', 'PHPSESSID', 'csrftoken'}


def now():
    return datetime.now(timezone.utc).isoformat()


def token(value):
    return 'sha256:' + hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:20]


def safe_name(value):
    return value if value in SAFE_NAMES else token(value)


def safe_url(value):
    """Conservative: keep host, known generic segments, strip all query/fragment values."""
    try:
        p = urlsplit(value)
        host = p.hostname or ''
        path = '/'.join(s if s in SAFE_SEGMENTS or not s else token(s) for s in p.path.split('/'))
        return urlunsplit((p.scheme, '['+host+']' if ':' in host else host, path, 'redacted' if p.query else '', ''))
    except ValueError:
        return token(value)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def artifact(data):
    raw = canonical(data)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'data': data}
