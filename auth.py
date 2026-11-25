import hmac
import time
import uuid
import requests
from flask import Blueprint, jsonify, request, session

from core.config import GOOGLE_CLIENT_ID, get_admin_passkey
from core.security import (
    client_ip,
    ensure_csrf_token,
    invalidate_user_state,
    log_admin_audit,
    log_security,
    login_required,
    recent_event_count,
)
from database import generate_referral_code, get_db, hash_password, verify_password

auth_bp = Blueprint('auth', __name__)

_failed_admin_attempts = {}
_failed_login_attempts = {}


@auth_bp.route('/api/admin/verify-passkey', methods=['POST'])
def verify_admin_passkey():
    ip = client_ip()
    now = time.time()

    record = _failed_admin_attempts.get(ip, {'count': 0, 'lock_until': 0})
    db_fails = recent_event_count('admin_fail', 600, ip=ip)
    if record['lock_until'] > now or db_fails >= 5:
        log_security('admin_lock', 'locked address tried again')
        return jsonify({'error': 'Too many failed attempts. This address is locked for 10 minutes.'}), 429

    if session.get('role') != 'admin' or 'user_id' not in session:
        log_security('admin_fail', 'passkey used without an owner login')
        return jsonify({'error': 'Sign in with the owner account first. The passkey alone does not open this panel.'}), 403

    data = request.get_json() or {}
    passkey = (data.get('passkey') or '').strip()
    if not passkey:
        return jsonify({'error': 'Passkey is required.'}), 400

    if hmac.compare_digest(passkey, get_admin_passkey()):
        _failed_admin_attempts.pop(ip, None)
        session['admin_passkey_verified'] = True
        session.permanent = False
        ensure_csrf_token()
        log_security('admin_ok', 'owner passkey accepted')
        log_admin_audit('admin_unlock', target=session.get('username', ''), detail='Unlocked admin gate')
        return jsonify({'success': True, 'message': 'Access granted'})

    new_count = max(record['count'], db_fails) + 1
    lock_until = now + 600 if new_count >= 5 else 0
    _failed_admin_attempts[ip] = {'count': new_count, 'lock_until': lock_until}
    log_security('admin_fail', 'wrong passkey')

    if new_count >= 5:
        return jsonify({'error': 'Too many failed attempts. This address is locked for 10 minutes.'}), 429
    return jsonify({'error': 'Access denied.'}), 401


@auth_bp.route('/api/admin/lock', methods=['POST'])
def lock_admin():
    session.pop('admin_passkey_verified', None)
    if session.get('role') == 'admin':
        session.clear()
    return jsonify({'success': True, 'message': 'Admin session locked.'})


@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    ip = client_ip()
    if recent_event_count('register_ok', 3600, ip=ip) >= 8:
        log_security('register_rate_limit', 'excessive signups from IP')
        return jsonify({'error': 'Too many accounts created from this network recently. Try again later.'}), 429

    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    ref_code_input = (data.get('ref') or '').strip().upper()

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required.'}), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({'error': 'Username must be between 3 and 30 characters.'}), 400

    if not username.replace('_', '').replace('-', '').isalnum():
        return jsonify({'error': 'Username can only contain letters, numbers, hyphens, and underscores.'}), 400

    if '@' not in email or '.' not in email.split('@')[-1] or len(email) > 120:
        return jsonify({'error': 'Enter a valid email address.'}), 400

    if len(password) < 6 or len(password) > 128:
        return jsonify({'error': 'Password must be between 6 and 128 characters.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR email = ?', (username, email))
        if cursor.fetchone():
            return jsonify({'error': 'Username or Email is already registered.'}), 409

        referred_by = None
        if ref_code_input:
            cursor.execute('SELECT id FROM users WHERE referral_code = ?', (ref_code_input,))
            ref_row = cursor.fetchone()
            if ref_row:
                referred_by = ref_row['id']

        new_ref_code = generate_referral_code(cursor)
        pw_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, balance, role, referral_code, referred_by, referral_earnings, is_banned, session_version)
            VALUES (?, ?, ?, 0.0, 'user', ?, ?, 0.0, 0, 1)
        ''', (username, email, pw_hash, new_ref_code, referred_by))
        conn.commit()
        log_security('register_ok', f'registered @{username}')

        return jsonify({
            'success': True,
            'message': 'Account created! Sign in with your credentials.',
            'username': username
        }), 201
    except Exception:
        conn.rollback()
        return jsonify({'error': 'Registration failed. Please try again.'}), 500
    finally:
        conn.close()


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    ip = client_ip()
    now = time.time()

    record = _failed_login_attempts.get(ip, {'count': 0, 'lock_until': 0})
    db_fails = recent_event_count('login_fail', 600, ip=ip)
    if record['lock_until'] > now or db_fails >= 8:
        remaining_secs = max(60, int(record['lock_until'] - now))
        return jsonify({
            'error': f'Too many failed login attempts. Try again in {remaining_secs} seconds.'
        }), 429

    data = request.get_json() or {}
    identifier = (data.get('identifier') or '').strip()
    password = data.get('password') or ''

    if not identifier or not password:
        return jsonify({'error': 'Enter your username/email and password.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT id, username, email, password_hash, balance, role, referral_code, is_banned, ban_reason, session_version
            FROM users
            WHERE username = ? OR email = ?
        ''', (identifier, identifier.lower()))
        user = cursor.fetchone()

        valid = False
        needs_rehash = False
        if user:
            valid, needs_rehash = verify_password(user['password_hash'], password)

        if not valid:
            log_security('login_fail', f'bad login for {identifier[:32]}')
            new_count = max(record['count'], db_fails) + 1
            if new_count >= 10:
                lock_until = now + 900
            elif new_count >= 5:
                lock_until = now + 180
            else:
                lock_until = 0
            _failed_login_attempts[ip] = {'count': new_count, 'lock_until': lock_until}

            if lock_until > 0:
                lock_mins = max(1, int((lock_until - now) / 60))
                return jsonify({'error': f'Too many failed attempts. Locked for {lock_mins} minute(s).'}), 429

            remaining = max(1, 5 - (new_count % 5))
            return jsonify({'error': f'Invalid credentials ({remaining} attempt(s) before lockout).'}), 401

        if int(user['is_banned'] or 0):
            reason = user['ban_reason'] or 'This account has been suspended.'
            log_security('banned_login', f"banned user @{user['username']}")
            return jsonify({'error': f'Account suspended: {reason}'}), 403

        if needs_rehash:
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(password), user['id']))
            conn.commit()

        _failed_login_attempts.pop(ip, None)
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['session_version'] = int(user['session_version'] or 1)
        csrf = ensure_csrf_token()
        invalidate_user_state(user['id'])

        return jsonify({
            'success': True,
            'message': 'Logged in!',
            'csrf_token': csrf,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'balance': float(user['balance']),
                'role': user['role'],
                'referral_code': user['referral_code'] or '',
            }
        })
    finally:
        conn.close()


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    if uid:
        invalidate_user_state(int(uid))
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out.'})


@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or {}
    current_pw = data.get('current_password') or ''
    new_pw = data.get('new_password') or ''

    if not current_pw or not new_pw:
        return jsonify({'error': 'Current and new passwords are required.'}), 400
    if len(new_pw) < 6 or len(new_pw) > 128:
        return jsonify({'error': 'New password must be between 6 and 128 characters.'}), 400

    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT password_hash, session_version FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'User not found.'}), 404

        valid, _ = verify_password(row['password_hash'], current_pw)
        if not valid:
            log_security('pw_change_fail', 'wrong current password')
            return jsonify({'error': 'Current password is incorrect.'}), 401

        next_ver = int(row['session_version'] or 1) + 1
        cursor.execute(
            'UPDATE users SET password_hash = ?, session_version = ? WHERE id = ?',
            (hash_password(new_pw), next_ver, user_id)
        )
        conn.commit()
        session['session_version'] = next_ver
        invalidate_user_state(user_id)
        log_security('pw_change_ok', 'password updated')
        return jsonify({'success': True, 'message': 'Password updated and other active sessions signed out.'})
    finally:
        conn.close()


@auth_bp.route('/api/auth/google', methods=['POST'])
def google_auth():
    if not GOOGLE_CLIENT_ID:
        log_security('google_auth_disabled', 'attempt while GOOGLE_CLIENT_ID unset')
        return jsonify({'error': 'Google Sign-In is not configured on this server.'}), 403

    data = request.get_json() or {}
    id_token = (data.get('id_token') or '').strip()
    ref_code_input = (data.get('ref') or '').strip().upper()
    if not id_token:
        log_security('google_auth_reject', 'missing Google id_token')
        return jsonify({'error': 'Verified Google ID token is required.'}), 400

    try:
        verify_res = requests.get(
            'https://oauth2.googleapis.com/tokeninfo',
            params={'id_token': id_token},
            timeout=8,
        )
        if verify_res.status_code != 200:
            log_security('google_auth_reject', 'invalid Google id_token')
            return jsonify({'error': 'Invalid Google credential.'}), 401
        token_info = verify_res.json()
    except Exception:
        return jsonify({'error': 'Could not verify Google token.'}), 502

    if token_info.get('aud') != GOOGLE_CLIENT_ID or token_info.get('email_verified') not in ('true', True):
        log_security('google_auth_reject', 'Google audience or email_verified mismatch')
        return jsonify({'error': 'Google token verification failed.'}), 401

    email = (token_info.get('email') or '').strip().lower()
    name = (token_info.get('name') or '').strip()
    if not email:
        return jsonify({'error': 'Email missing from verified Google token.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, email, balance, role, referral_code, is_banned, ban_reason, session_version FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            base_username = name.replace(' ', '').lower() if name else email.split('@')[0]
            base_username = ''.join(c for c in base_username if c.isalnum())[:16] or 'user'
            username = base_username
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            suffix = 1
            while cursor.fetchone():
                username = f"{base_username}{suffix}"
                cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                suffix += 1

            referred_by = None
            if ref_code_input:
                cursor.execute('SELECT id FROM users WHERE referral_code = ?', (ref_code_input,))
                ref_row = cursor.fetchone()
                if ref_row:
                    referred_by = ref_row['id']

            new_ref_code = generate_referral_code(cursor)
            random_pwd = uuid.uuid4().hex + uuid.uuid4().hex
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, balance, role, referral_code, referred_by, referral_earnings, is_banned, session_version)
                VALUES (?, ?, ?, 0.0, 'user', ?, ?, 0.0, 0, 1)
            ''', (username, email, hash_password(random_pwd), new_ref_code, referred_by))
            conn.commit()
            new_user_id = cursor.lastrowid
            user = {
                'id': new_user_id,
                'username': username,
                'email': email,
                'balance': 0.0,
                'role': 'user',
                'referral_code': new_ref_code,
                'is_banned': 0,
                'session_version': 1,
            }
        else:
            user = dict(user)
            if int(user.get('is_banned') or 0):
                return jsonify({'error': f"Account suspended: {user.get('ban_reason') or 'Banned'}"}), 403
            if not user.get('referral_code'):
                user['referral_code'] = generate_referral_code(cursor)
                cursor.execute('UPDATE users SET referral_code = ? WHERE id = ?', (user['referral_code'], user['id']))
                conn.commit()

        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['session_version'] = int(user.get('session_version') or 1)
        csrf = ensure_csrf_token()

        return jsonify({
            'success': True,
            'csrf_token': csrf,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'balance': float(user['balance']),
                'role': user['role'],
                'referral_code': user.get('referral_code') or '',
            }
        })
    finally:
        conn.close()


@auth_bp.route('/api/auth/me', methods=['GET'])
def get_current_user():
    csrf = ensure_csrf_token()
    if 'user_id' not in session:
        return jsonify({'authenticated': False, 'csrf_token': csrf}), 200

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'SELECT id, username, email, balance, role, referral_code, is_banned, session_version FROM users WHERE id = ?',
            (session['user_id'],)
        )
        user = cursor.fetchone()
        if not user or int(user['is_banned'] or 0):
            session.clear()
            return jsonify({'authenticated': False, 'csrf_token': ensure_csrf_token()}), 200

        sess_ver = session.get('session_version')
        if sess_ver is not None and int(sess_ver) != int(user['session_version'] or 1):
            session.clear()
            return jsonify({'authenticated': False, 'csrf_token': ensure_csrf_token()}), 200

        ref_code = user['referral_code']
        if not ref_code:
            ref_code = generate_referral_code(cursor)
            cursor.execute('UPDATE users SET referral_code = ? WHERE id = ?', (ref_code, user['id']))
            conn.commit()

        return jsonify({
            'authenticated': True,
            'csrf_token': csrf,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'balance': float(user['balance']),
                'role': user['role'],
                'referral_code': ref_code,
            }
        })
    finally:
        conn.close()
