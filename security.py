import hmac
import secrets
import time
from functools import wraps
from urllib.parse import urlparse
from flask import jsonify, redirect, render_template, request, session, url_for

from database import get_db, is_postgres

PROBE_MARKERS = (
    '.env', 'wp-login', 'wp-admin', 'phpmyadmin', 'xmlrpc.php',
    '.git', '/etc/passwd', 'admin.php', 'phpunit', 'eval-stdin',
    'config.php', '.aws', 'id_rsa', 'wp-config',
)

_blocked_ips_cache = {'ips': set(), 'ts': 0.0}
_user_state_cache = {}


def invalidate_blocked_ips_cache():
    _blocked_ips_cache['ts'] = 0.0


def invalidate_user_state(user_id: int):
    _user_state_cache.pop(int(user_id), None)


def client_ip() -> str:
    cf_ip = request.headers.get('CF-Connecting-IP', '').strip()
    if cf_ip:
        return cf_ip[:80]
    xff = request.headers.get('X-Forwarded-For', '').strip()
    if xff:
        return xff.split(',')[0].strip()[:80]
    return (request.remote_addr or 'unknown')[:80]


def is_ip_blocked(ip: str) -> bool:
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        return False
    now = time.time()
    if now - _blocked_ips_cache['ts'] > 15.0:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT ip FROM blocked_ips')
            _blocked_ips_cache['ips'] = {
                (r['ip'] if isinstance(r, dict) or hasattr(r, 'keys') else r[0])
                for r in cur.fetchall()
            }
            _blocked_ips_cache['ts'] = now
            conn.close()
        except Exception:
            pass
    return ip in _blocked_ips_cache['ips']


def log_security(kind: str, detail: str = '', path: str = None):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO security_events (ip, kind, path, user_agent, detail)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            client_ip(),
            kind[:40],
            (path or request.path or '')[:180],
            (request.headers.get('User-Agent') or '')[:240],
            (detail or '')[:240],
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass


def recent_event_count(kind: str, seconds: int = 600, ip: str = None) -> int:
    target_ip = ip or client_ip()
    conn = get_db()
    cur = conn.cursor()
    try:
        if is_postgres():
            cur.execute(
                f"SELECT COUNT(*) AS c FROM security_events WHERE ip = ? AND kind = ? AND created_at >= NOW() - INTERVAL '{int(seconds)} seconds'",
                (target_ip, kind)
            )
        else:
            cur.execute(
                "SELECT COUNT(*) AS c FROM security_events WHERE ip = ? AND kind = ? AND created_at >= datetime('now', ?)",
                (target_ip, kind, f'-{int(seconds)} seconds')
            )
        row = cur.fetchone()
        if not row:
            return 0
        return int(row['c'] if isinstance(row, dict) or hasattr(row, 'keys') else row[0])
    except Exception:
        return 0
    finally:
        conn.close()


def log_admin_audit(action: str, target: str = '', detail: str = '', cursor=None):
    admin_user = session.get('username') or f"admin#{session.get('user_id', '0')}"
    ip = client_ip()
    own_conn = None
    try:
        if cursor is None:
            own_conn = get_db()
            cursor = own_conn.cursor()
        cursor.execute('''
            INSERT INTO admin_audit_logs (admin_user, action, target, detail, ip)
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_user[:60], action[:60], (target or '')[:120], (detail or '')[:300], ip))
        if own_conn is not None:
            own_conn.commit()
    except Exception:
        pass
    finally:
        if own_conn is not None:
            own_conn.close()


def ensure_csrf_token() -> str:
    tok = session.get('csrf_token')
    if not tok:
        tok = secrets.token_hex(24)
        session['csrf_token'] = tok
    return tok


def _check_session_user_valid(user_id: int) -> tuple[bool, str]:
    now = time.time()
    cached = _user_state_cache.get(user_id)
    if not cached or now - cached['ts'] > 10.0:
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute('SELECT is_banned, ban_reason, session_version, role FROM users WHERE id = ?', (user_id,))
            row = cur.fetchone()
            if not row:
                _user_state_cache.pop(user_id, None)
                return False, 'Account not found.'
            cached = {
                'is_banned': int(row['is_banned'] or 0),
                'ban_reason': row['ban_reason'] or 'Account suspended.',
                'session_version': int(row['session_version'] or 1),
                'role': row['role'] or 'user',
                'ts': now,
            }
            _user_state_cache[user_id] = cached
        finally:
            conn.close()

    if cached['is_banned']:
        return False, cached['ban_reason']

    sess_ver = session.get('session_version')
    if sess_ver is not None and int(sess_ver) != cached['session_version']:
        return False, 'Session expired. Please sign in again.'

    session['role'] = cached['role']
    return True, ''


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required. Please log in.'}), 401
            return redirect(url_for('pages.login_page'))

        ok, reason = _check_session_user_valid(int(session['user_id']))
        if not ok:
            session.clear()
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': reason}), 403
            return redirect(url_for('pages.login_page'))

        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            ok, reason = _check_session_user_valid(int(session['user_id']))
            if not ok:
                session.clear()
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': reason}), 403
                return redirect(url_for('pages.login_page'))

        if not session.get('admin_passkey_verified') or session.get('role') != 'admin':
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Master authorization required.'}), 403
            ensure_csrf_token()
            return render_template('admin_gate.html')
        return f(*args, **kwargs)
    return decorated_function


def register_security_middleware(app):
    @app.context_processor
    def inject_security_globals():
        return {'csrf_token': ensure_csrf_token}

    @app.before_request
    def enforce_request_security():
        path = (request.path or '').lower()
        if any(marker in path for marker in PROBE_MARKERS):
            log_security('probe', 'blocked scanner path')
            return jsonify({'error': 'Not found'}), 404

        if not path.startswith('/static/') and is_ip_blocked(client_ip()):
            log_security('ip_blocked', 'blocked IP request rejected')
            if request.is_json or path.startswith('/api/'):
                return jsonify({'error': 'Access from your IP address has been restricted.'}), 403
            return 'Access restricted.', 403

        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and path.startswith('/api/'):
            if path == '/api/webhooks/paymongo':
                return None

            origin = request.headers.get('Origin', '').strip()
            if origin:
                parsed = urlparse(origin)
                if parsed.netloc and parsed.netloc.lower() != request.host.lower():
                    log_security('csrf_block', f'mismatched origin {parsed.netloc}')
                    return jsonify({'error': 'Cross-origin request blocked.'}), 403

            sec_site = request.headers.get('Sec-Fetch-Site', '').strip().lower()
            if sec_site == 'cross-site':
                log_security('csrf_block', 'cross-site fetch rejected')
                return jsonify({'error': 'Cross-site request blocked.'}), 403

            if session.get('user_id') and session.get('csrf_token'):
                header_tok = request.headers.get('X-CSRF-Token', '').strip()
                if not header_tok or not hmac.compare_digest(header_tok, session['csrf_token']):
                    log_security('csrf_block', 'missing or invalid CSRF token')
                    return jsonify({'error': 'Security token expired or missing. Refresh the page and try again.'}), 403

    @app.after_request
    def apply_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
        if 'csrf_token' in session and request.path.startswith('/api/auth/'):
            response.headers['X-CSRF-Token'] = session['csrf_token']
        return response
