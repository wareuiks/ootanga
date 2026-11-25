import calendar
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.utils import secure_filename

from core.config import ALLOWED_IMAGE_EXTS, MAX_IMAGE_BYTES, get_setting, set_setting
from core.security import (
    admin_required,
    client_ip,
    invalidate_blocked_ips_cache,
    invalidate_user_state,
    log_admin_audit,
)
from database import get_db, hash_password, is_postgres

admin_bp = Blueprint('admin', __name__)


def _month_of(value) -> str:
    text = str(value or '')
    return text[:7] if len(text) >= 7 else 'unknown'


def _categorize_order(product_name: str) -> str:
    low = (product_name or '').lower()
    if any(k in low for k in ['source', 'code', 'src', 'github', 'repo']):
        return 'Source Code'
    if any(k in low for k in ['ios', 'cloud', 'apple', 'iphone', 'ipad']):
        return 'Cloud iOS'
    return 'Kova Android'


def _parse_features_input(raw_features) -> str:
    if isinstance(raw_features, list):
        items = [str(f).strip() for f in raw_features if str(f).strip()]
    elif isinstance(raw_features, str):
        stripped = raw_features.strip()
        if stripped.startswith('['):
            try:
                parsed = json.loads(stripped)
                items = [str(f).strip() for f in parsed if str(f).strip()] if isinstance(parsed, list) else []
            except Exception:
                items = [line.strip() for line in stripped.splitlines() if line.strip()]
        else:
            items = [line.strip() for line in stripped.splitlines() if line.strip()]
    else:
        items = []
    return json.dumps(items)


def _generate_voucher_code(cursor, pct: int, scope: str = 'lifetime') -> str:
    prefix = f"KOVA-LIFE{pct}-" if scope == 'lifetime' else f"KOVA-{pct}OFF-"
    for _ in range(32):
        code = prefix + secrets.token_hex(3).upper()
        cursor.execute('SELECT id FROM vouchers WHERE code = ?', (code,))
        if not cursor.fetchone():
            return code
    return prefix + uuid.uuid4().hex[:8].upper()


@admin_bp.route('/api/admin/overview', methods=['GET'])
@admin_required
def admin_overview():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT COUNT(*) as total_users FROM users')
        total_users = int(cursor.fetchone()['total_users'] or 0)

        cursor.execute('SELECT COUNT(*) as total_orders, COALESCE(SUM(price), 0) as total_revenue FROM orders')
        order_stats = cursor.fetchone()

        direct_orders = 0
        direct_revenue = 0.0
        try:
            cursor.execute("SELECT COUNT(*) as c, COALESCE(SUM(amount), 0) as r FROM ledger_entries WHERE entry_type IN ('sale', 'direct_sale')")
            d_res = cursor.fetchone()
            direct_orders = int(d_res['c'] or 0)
            direct_revenue = float(d_res['r'] or 0.0)
        except Exception:
            pass

        cursor.execute('SELECT COUNT(*) as available_keys FROM license_keys WHERE is_used = 0')
        available_keys = int(cursor.fetchone()['available_keys'] or 0)

        cursor.execute('SELECT COUNT(*) as used_keys FROM license_keys WHERE is_used = 1')
        used_keys = int(cursor.fetchone()['used_keys'] or 0)

        cursor.execute('''
            SELECT u.id, u.username, u.email, u.balance, u.role, COALESCE(u.is_banned, 0) AS is_banned, u.ban_reason, u.created_at
            FROM users u
            ORDER BY u.id DESC
            LIMIT 100
        ''')
        users = [dict(row) for row in cursor.fetchall()]

        cursor.execute('''
            SELECT p.id, p.name, p.duration, p.price,
                   (SELECT COUNT(*) FROM license_keys WHERE product_id = p.id AND is_used = 0) as stock
            FROM products p
            WHERE COALESCE(p.is_active, 1) = 1
            ORDER BY p.price ASC
        ''')
        products = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'total_users': total_users,
            'total_orders': int(order_stats['total_orders'] or 0) + direct_orders,
            'total_revenue': float(order_stats['total_revenue'] or 0.0) + direct_revenue,
            'available_keys': available_keys,
            'used_keys': used_keys,
            'users': users,
            'products': products,
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/keys/add', methods=['POST'])
@admin_required
def admin_add_keys():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    raw_keys = data.get('keys', '')

    if not product_id or not raw_keys:
        return jsonify({'error': 'Product and keys are required.'}), 400

    key_list = [k.strip() for k in raw_keys.split('\n') if k.strip()]
    if not key_list:
        return jsonify({'error': 'No valid keys provided.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    added = 0
    try:
        for key_text in key_list:
            try:
                cursor.execute('INSERT INTO license_keys (product_id, license_key, is_used) VALUES (?, ?, 0)', (product_id, key_text))
                added += 1
            except Exception:
                pass
        log_admin_audit('keys_import', target=f'product#{product_id}', detail=f'Imported {added} key(s)', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'added': added, 'message': f'Imported {added} keys!'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/keys', methods=['GET'])
@admin_required
def admin_get_keys():
    status = request.args.get('status', 'all')
    product_id = request.args.get('product_id', 'all')
    search = (request.args.get('search') or '').strip()

    query = '''
        SELECT k.id, k.license_key, k.is_used, k.created_at, k.used_at,
               COALESCE(p.name, 'Digital Product') as product_name,
               COALESCE(p.duration, 'Standard') as duration,
               COALESCE(u.username, 'Customer') as claimed_by_user,
               COALESCE(
                   (SELECT o.order_id FROM orders o WHERE TRIM(o.license_key) = TRIM(k.license_key) ORDER BY o.id DESC LIMIT 1),
                   (SELECT o.order_id FROM orders o WHERE o.user_id = k.assigned_to_user_id AND o.product_id = k.product_id ORDER BY o.id DESC LIMIT 1)
               ) as order_id
        FROM license_keys k
        LEFT JOIN products p ON k.product_id = p.id
        LEFT JOIN users u ON k.assigned_to_user_id = u.id
        WHERE 1=1
    '''
    params = []
    if status == 'available':
        query += ' AND k.is_used = 0'
    elif status == 'used':
        query += ' AND k.is_used = 1'

    if product_id != 'all' and product_id.isdigit():
        query += ' AND k.product_id = ?'
        params.append(int(product_id))

    if search:
        like_q = f'%{search.lower()}%'
        query += " AND (LOWER(k.license_key) LIKE ? OR LOWER(COALESCE(u.username, '')) LIKE ? OR LOWER(COALESCE(p.name, '')) LIKE ?)"
        params.extend([like_q, like_q, like_q])

    query += ' ORDER BY k.id DESC LIMIT 250'

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(query, tuple(params))
        return jsonify({'keys': [dict(row) for row in cursor.fetchall()]})
    finally:
        conn.close()


@admin_bp.route('/api/admin/keys/delete', methods=['POST'])
@admin_required
def admin_delete_key():
    data = request.get_json() or {}
    key_ids = data.get('ids', [])
    single_id = data.get('id')
    if single_id is not None:
        if isinstance(key_ids, list):
            if single_id not in key_ids:
                key_ids.append(single_id)
        else:
            key_ids = [single_id]

    if not key_ids or not isinstance(key_ids, list):
        return jsonify({'error': 'Select at least one key to delete.'}), 400

    clean_ids = [int(k) for k in key_ids if str(k).isdigit()]
    if not clean_ids:
        return jsonify({'error': 'Invalid key IDs.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        placeholders = ', '.join(['?'] * len(clean_ids))
        cursor.execute(f'DELETE FROM license_keys WHERE id IN ({placeholders})', tuple(clean_ids))
        deleted = cursor.rowcount
        log_admin_audit('keys_delete', detail=f'Deleted {deleted} key(s)', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'message': f'Deleted {deleted} key(s) from inventory.', 'deleted_count': deleted})
    finally:
        conn.close()


@admin_bp.route('/api/admin/keys/bring-back', methods=['POST'])
@admin_required
def admin_bring_back_key():
    data = request.get_json() or {}
    key_id = data.get('id')
    bring_all = data.get('all', False)

    conn = get_db()
    cursor = conn.cursor()
    try:
        if bring_all:
            cursor.execute('UPDATE license_keys SET is_used = 0, assigned_to_user_id = NULL, used_at = NULL WHERE is_used = 1')
            restored = cursor.rowcount
        elif key_id:
            cursor.execute('UPDATE license_keys SET is_used = 0, assigned_to_user_id = NULL, used_at = NULL WHERE id = ? AND is_used = 1', (key_id,))
            restored = cursor.rowcount
        else:
            return jsonify({'error': 'Key ID or all parameter is required.'}), 400

        if restored == 0 and not bring_all:
            conn.rollback()
            return jsonify({'error': 'Key is already available or not found.'}), 400

        log_admin_audit('keys_restock', detail=f'Restored {restored} key(s)', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'restored': restored, 'message': f'Restored {restored} key(s) to stock!'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/users/balance', methods=['POST'])
@admin_required
def admin_adjust_balance():
    data = request.get_json() or {}
    reason = (data.get('reason') or 'Admin adjustment').strip()[:200]
    try:
        amount = round(float(data.get('amount')), 2)
        target_user_id = int(data.get('user_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid user ID or amount.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, target_user_id))
        ref_id = f"ADM-ADJ-{uuid.uuid4().hex[:6].upper()}"
        cursor.execute('''
            INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
            VALUES (?, ?, 'admin_adjustment', ?, 'completed', ?)
        ''', (ref_id, target_user_id, amount, reason))
        log_admin_audit('balance_adjust', target=f'user#{target_user_id}', detail=f'₱{amount:+.2f} ({reason})', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'message': f'Balance adjusted by ₱{amount:+.2f}'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/users/<int:target_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(target_id):
    if int(target_id) == int(session.get('user_id', 0)):
        return jsonify({'error': 'You cannot suspend your own account.'}), 400

    data = request.get_json() or {}
    banned = 1 if bool(data.get('banned', True)) else 0
    reason = (data.get('reason') or 'Suspended by administrator').strip()[:200] if banned else None

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, role, session_version FROM users WHERE id = ?', (target_id,))
        u = cursor.fetchone()
        if not u:
            return jsonify({'error': 'User not found.'}), 404
        if u['role'] == 'admin' and banned:
            return jsonify({'error': 'Cannot suspend another admin account.'}), 400

        next_ver = int(u['session_version'] or 1) + 1
        cursor.execute(
            'UPDATE users SET is_banned = ?, ban_reason = ?, session_version = ? WHERE id = ?',
            (banned, reason, next_ver, target_id)
        )
        log_admin_audit(
            'user_ban' if banned else 'user_unban',
            target=f"@{u['username']}",
            detail=reason or 'Account restored',
            cursor=cursor,
        )
        conn.commit()
        invalidate_user_state(target_id)
        return jsonify({
            'success': True,
            'message': f"@{u['username']} {'suspended' if banned else 'restored'}.",
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/users/<int:target_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_user_password(target_id):
    data = request.get_json() or {}
    new_pw = (data.get('new_password') or '').strip()
    generated = False
    if not new_pw:
        new_pw = 'Kova-' + secrets.token_urlsafe(6)
        generated = True
    elif len(new_pw) < 6 or len(new_pw) > 128:
        return jsonify({'error': 'Password must be between 6 and 128 characters.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, session_version FROM users WHERE id = ?', (target_id,))
        u = cursor.fetchone()
        if not u:
            return jsonify({'error': 'User not found.'}), 404

        next_ver = int(u['session_version'] or 1) + 1
        cursor.execute(
            'UPDATE users SET password_hash = ?, session_version = ? WHERE id = ?',
            (hash_password(new_pw), next_ver, target_id)
        )
        log_admin_audit('user_pw_reset', target=f"@{u['username']}", detail='Admin reset password & invalidated sessions', cursor=cursor)
        conn.commit()
        invalidate_user_state(target_id)
        return jsonify({
            'success': True,
            'temporary_password': new_pw if generated else None,
            'message': f"Password reset for @{u['username']}.",
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/customers/activity', methods=['GET'])
@admin_required
def admin_customer_activity():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT o.id, o.order_id, o.user_id, COALESCE(u.username, 'User #' || o.user_id) as username,
                   u.email, o.product_id, o.product_name, o.price, o.license_key, o.voucher_code, o.discount_amount, o.created_at
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.id DESC
            LIMIT 250
        ''')
        purchases = [dict(row) for row in cur.fetchall()]

        cur.execute('''
            SELECT t.id, t.reference_id, t.user_id, COALESCE(u.username, 'User #' || t.user_id) as username,
                   u.email, t.type, t.amount, t.status, t.description, t.created_at
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.type IN ('deposit', 'admin_adjustment')
            ORDER BY t.id DESC
            LIMIT 250
        ''')
        deposits = [dict(row) for row in cur.fetchall()]

        cur.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0.0) as total FROM transactions WHERE type = 'deposit' AND status = 'completed'")
        dep_stat = cur.fetchone() or {'cnt': 0, 'total': 0.0}

        cur.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(price), 0.0) as total FROM orders")
        ord_stat = cur.fetchone() or {'cnt': 0, 'total': 0.0}

        return jsonify({
            'purchases': purchases,
            'deposits': deposits,
            'stats': {
                'total_deposits_count': int(dep_stat['cnt'] or 0),
                'total_deposits_amount': float(dep_stat['total'] or 0.0),
                'total_orders_count': int(ord_stat['cnt'] or 0),
                'total_orders_amount': float(ord_stat['total'] or 0.0),
            }
        })
    finally:
        conn.close()


# ── VOUCHERS MANAGEMENT (20% / 50% / 65% LIFETIME KEYS) ──

@admin_bp.route('/api/admin/vouchers', methods=['GET'])
@admin_required
def admin_list_vouchers():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT id, code, discount_percent, tier_scope, max_uses, used_count, per_user_limit,
                   expires_at, note, is_active, created_by, created_at
            FROM vouchers
            ORDER BY id DESC
            LIMIT 200
        ''')
        vouchers = []
        active_count = 0
        for r in cursor.fetchall():
            item = dict(r)
            item['created_at'] = str(item.get('created_at') or '')
            if int(item.get('is_active') or 0):
                active_count += 1
            vouchers.append(item)

        cursor.execute('''
            SELECT vu.id, vu.voucher_code, vu.order_id, vu.original_price, vu.discount_amount, vu.final_price, vu.created_at,
                   COALESCE(u.username, 'User #' || vu.user_id) AS username
            FROM voucher_usages vu
            LEFT JOIN users u ON vu.user_id = u.id
            ORDER BY vu.id DESC
            LIMIT 100
        ''')
        usages = []
        for r in cursor.fetchall():
            d = dict(r)
            d['created_at'] = str(d.get('created_at') or '')
            usages.append(d)

        cursor.execute('SELECT COUNT(*) AS cnt, COALESCE(SUM(discount_amount), 0.0) AS saved FROM voucher_usages')
        st = cursor.fetchone() or {'cnt': 0, 'saved': 0.0}

        return jsonify({
            'vouchers': vouchers,
            'usages': usages,
            'stats': {
                'active_count': active_count,
                'total_redemptions': int(st['cnt'] or 0),
                'total_discounted': round(float(st['saved'] or 0.0), 2),
            }
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/vouchers', methods=['POST'])
@admin_required
def admin_create_voucher():
    data = request.get_json() or {}
    try:
        discount_percent = int(data.get('discount_percent', 20))
        max_uses = max(0, int(data.get('max_uses', 1)))
        per_user_limit = max(0, int(data.get('per_user_limit', 1)))
        batch_count = min(50, max(1, int(data.get('count', 1))))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid numeric fields for voucher.'}), 400

    if discount_percent < 1 or discount_percent > 95:
        return jsonify({'error': 'Discount percent must be between 1% and 95%.'}), 400

    tier_scope = (data.get('tier_scope') or 'lifetime').strip().lower()
    if tier_scope not in ('lifetime', 'all'):
        tier_scope = 'lifetime'

    custom_code = (data.get('code') or '').strip().upper()
    if custom_code:
        cleaned = ''.join(c for c in custom_code if c.isalnum() or c in ('-', '_'))[:32]
        if len(cleaned) < 3:
            return jsonify({'error': 'Custom voucher code must be at least 3 characters.'}), 400
        custom_code = cleaned

    expires_at = (data.get('expires_at') or '').strip()[:10] or None
    note = (data.get('note') or '').strip()[:200]
    admin_user = session.get('username') or f"admin#{session.get('user_id', 0)}"

    conn = get_db()
    cursor = conn.cursor()
    created_codes = []
    try:
        if custom_code and batch_count == 1:
            cursor.execute('SELECT id FROM vouchers WHERE UPPER(code) = ?', (custom_code,))
            if cursor.fetchone():
                return jsonify({'error': f'Voucher code "{custom_code}" already exists.'}), 409
            cursor.execute('''
                INSERT INTO vouchers (code, discount_percent, tier_scope, max_uses, used_count, per_user_limit, expires_at, note, is_active, created_by)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?, 1, ?)
            ''', (custom_code, discount_percent, tier_scope, max_uses, per_user_limit, expires_at, note, admin_user))
            created_codes.append(custom_code)
        else:
            for _ in range(batch_count):
                code = _generate_voucher_code(cursor, discount_percent, tier_scope)
                cursor.execute('''
                    INSERT INTO vouchers (code, discount_percent, tier_scope, max_uses, used_count, per_user_limit, expires_at, note, is_active, created_by)
                    VALUES (?, ?, ?, ?, 0, ?, ?, ?, 1, ?)
                ''', (code, discount_percent, tier_scope, max_uses, per_user_limit, expires_at, note, admin_user))
                created_codes.append(code)

        log_admin_audit(
            'voucher_create',
            target=', '.join(created_codes[:3]),
            detail=f'{len(created_codes)}x {discount_percent}% ({tier_scope}) max_uses={max_uses}',
            cursor=cursor,
        )
        conn.commit()
        return jsonify({
            'success': True,
            'codes': created_codes,
            'message': f"Created {len(created_codes)} voucher(s) at {discount_percent}% off!",
        }), 201
    finally:
        conn.close()


@admin_bp.route('/api/admin/vouchers/<int:voucher_id>', methods=['PUT'])
@admin_required
def admin_update_voucher(voucher_id):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, code, is_active, max_uses, expires_at, note FROM vouchers WHERE id = ?', (voucher_id,))
        v = cursor.fetchone()
        if not v:
            return jsonify({'error': 'Voucher not found.'}), 404

        is_active = 1 if int(data.get('is_active', v['is_active'])) else 0
        max_uses = max(0, int(data.get('max_uses', v['max_uses'])))
        expires_at = (data.get('expires_at', v['expires_at']) or '').strip()[:10] or None
        note = (data.get('note', v['note']) or '').strip()[:200]

        cursor.execute('''
            UPDATE vouchers
            SET is_active = ?, max_uses = ?, expires_at = ?, note = ?
            WHERE id = ?
        ''', (is_active, max_uses, expires_at, note, voucher_id))
        log_admin_audit('voucher_update', target=v['code'], detail=f'active={is_active}, max_uses={max_uses}', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'message': f"Voucher {v['code']} updated."})
    finally:
        conn.close()


@admin_bp.route('/api/admin/vouchers/<int:voucher_id>', methods=['DELETE'])
@admin_required
def admin_delete_voucher(voucher_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, code, used_count FROM vouchers WHERE id = ?', (voucher_id,))
        v = cursor.fetchone()
        if not v:
            return jsonify({'error': 'Voucher not found.'}), 404

        if int(v['used_count'] or 0) > 0:
            cursor.execute('UPDATE vouchers SET is_active = 0 WHERE id = ?', (voucher_id,))
            log_admin_audit('voucher_archive', target=v['code'], detail='Deactivated redeemed voucher', cursor=cursor)
            conn.commit()
            return jsonify({'success': True, 'soft': True, 'message': f"Voucher {v['code']} has redemptions, so it was deactivated."})

        cursor.execute('DELETE FROM vouchers WHERE id = ?', (voucher_id,))
        log_admin_audit('voucher_delete', target=v['code'], detail='Deleted unused voucher', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'soft': False, 'message': f"Voucher {v['code']} deleted."})
    finally:
        conn.close()


# ── BOOKS, FUNDS, REVENUE ──

@admin_bp.route('/api/admin/books', methods=['GET'])
@admin_required
def admin_books():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('SELECT price, created_at FROM orders')
        orders = [dict(row) for row in cur.fetchall()]
        cur.execute("SELECT amount, created_at FROM transactions WHERE type = 'deposit' AND status = 'completed'")
        deposits = [dict(row) for row in cur.fetchall()]
        cur.execute('SELECT id, entry_type, amount, category, note, occurred_on, created_at FROM ledger_entries ORDER BY occurred_on DESC, id DESC')
        entries = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

    months = {}

    def bucket(key):
        if key not in months:
            months[key] = {'month': key, 'sales': 0.0, 'deposits': 0.0, 'spend': 0.0, 'added': 0.0, 'debt': 0.0, 'repay': 0.0}
        return months[key]

    for row in orders:
        bucket(_month_of(row['created_at']))['sales'] += float(row['price'] or 0)
    for row in deposits:
        bucket(_month_of(row['created_at']))['deposits'] += float(row['amount'] or 0)
    for entry in entries:
        kind = entry.get('entry_type')
        amt = float(entry.get('amount') or 0)
        m_k = _month_of(entry.get('occurred_on'))
        if kind in ('sale', 'direct_sale'):
            bucket(m_k)['sales'] += amt
        elif kind in ('spend', 'added', 'debt', 'repay'):
            bucket(m_k)[kind] += amt

    ordered = [months[k] for k in sorted(months.keys(), reverse=True)]
    for row in ordered:
        row['made'] = round(row['sales'] + row['added'] - row['spend'], 2)
        for key in ('sales', 'deposits', 'spend', 'added', 'debt', 'repay'):
            row[key] = round(row[key], 2)

    totals = {'sales': 0.0, 'deposits': 0.0, 'spend': 0.0, 'added': 0.0, 'debt': 0.0, 'repay': 0.0}
    for row in ordered:
        for key in totals:
            totals[key] += row[key]
    totals = {k: round(v, 2) for k, v in totals.items()}
    totals['open_debt'] = round(totals['debt'] - totals['repay'], 2)
    totals['made'] = round(totals['sales'] + totals['added'] - totals['spend'], 2)

    return jsonify({'months': ordered, 'entries': entries, 'totals': totals})


@admin_bp.route('/api/admin/books', methods=['POST'])
@admin_required
def admin_books_add():
    data = request.get_json() or {}
    entry_type = (data.get('entry_type') or '').strip()
    category = (data.get('category') or 'general').strip()
    note = (data.get('note') or '').strip()
    occurred_on = (data.get('occurred_on') or datetime.utcnow().strftime('%Y-%m-%d')).strip()[:10]

    valid_types = ('direct_sale', 'sale', 'spend', 'added', 'debt', 'repay')
    if entry_type not in valid_types:
        return jsonify({'error': 'Choose direct sale, spend, added money, debt, or a debt payment.'}), 400
    try:
        amount = round(float(data.get('amount')), 2)
    except (TypeError, ValueError):
        return jsonify({'error': 'Enter a valid amount.'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be greater than zero.'}), 400
    if len(occurred_on) != 10:
        return jsonify({'error': 'Use a date like 2026-11-08.'}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO ledger_entries (entry_type, amount, category, note, occurred_on)
            VALUES (?, ?, ?, ?, ?)
        ''', (entry_type, amount, category, note[:240], occurred_on))
        log_admin_audit('ledger_add', target=entry_type, detail=f'₱{amount:.2f} ({note[:60]})', cursor=cur)
        conn.commit()
        return jsonify({'success': True, 'message': 'Saved to the books.'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/books/<int:entry_id>', methods=['DELETE'])
@admin_required
def admin_books_delete(entry_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM ledger_entries WHERE id = ?', (entry_id,))
        log_admin_audit('ledger_delete', target=f'entry#{entry_id}', cursor=cur)
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@admin_bp.route('/api/admin/funds', methods=['GET'])
@admin_required
def admin_funds():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COALESCE(SUM(amount), 0.0) AS total FROM fund_adjustments WHERE adjustment_type = 'add'")
        added = float(cur.fetchone()['total'] or 0)
        cur.execute("SELECT COALESCE(SUM(amount), 0.0) AS total FROM fund_adjustments WHERE adjustment_type = 'remove'")
        removed = float(cur.fetchone()['total'] or 0)
        balance = round(added - removed, 2)

        cur.execute('''
            SELECT id, admin_user, amount, adjustment_type, target_user_id, target_username, note, created_at
            FROM fund_adjustments
            ORDER BY id DESC
            LIMIT 200
        ''')
        adjustments = [dict(row) for row in cur.fetchall()]

        cur.execute('''
            SELECT t.id, t.reference_id, t.user_id, COALESCE(u.username, 'User #' || t.user_id) as username,
                   u.email, t.type, t.amount, t.status, t.description, t.created_at
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.type IN ('deposit', 'admin_adjustment')
            ORDER BY t.id DESC
            LIMIT 250
        ''')
        customer_deposits = [dict(row) for row in cur.fetchall()]

        cur.execute('SELECT id, username, email, balance FROM users ORDER BY username ASC')
        users = [dict(row) for row in cur.fetchall()]

        return jsonify({
            'balance': balance,
            'total_added': round(added, 2),
            'total_removed': round(removed, 2),
            'adjustments': adjustments,
            'customer_deposits': customer_deposits,
            'users': users,
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/funds', methods=['POST'])
@admin_required
def admin_funds_add():
    data = request.get_json() or {}
    adjustment_type = (data.get('adjustment_type') or '').strip()
    note = (data.get('note') or '').strip()
    raw_user_id = data.get('user_id')

    if adjustment_type not in ('add', 'remove'):
        return jsonify({'error': 'Choose add or remove funds.'}), 400
    try:
        amount = round(float(data.get('amount')), 2)
    except (TypeError, ValueError):
        return jsonify({'error': 'Enter a valid amount.'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be greater than zero.'}), 400

    admin_user = session.get('username') or f"admin#{session.get('user_id')}"
    conn = get_db()
    cur = conn.cursor()
    try:
        target_user_id = None
        target_username = None
        if raw_user_id and str(raw_user_id).isdigit():
            target_user_id = int(raw_user_id)
            cur.execute('SELECT id, username, balance FROM users WHERE id = ?', (target_user_id,))
            u_row = cur.fetchone()
            if not u_row:
                return jsonify({'error': 'Selected customer does not exist.'}), 404
            target_username = u_row['username']
            delta = amount if adjustment_type == 'add' else -amount
            new_bal = max(0.0, round(float(u_row['balance'] or 0) + delta, 2))
            cur.execute('UPDATE users SET balance = ? WHERE id = ?', (new_bal, target_user_id))
            ref_id = f"ADM-FND-{uuid.uuid4().hex[:6].upper()}"
            desc = note[:200] if note else f"Admin {adjustment_type} funds by @{admin_user}"
            cur.execute('''
                INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
                VALUES (?, ?, 'admin_adjustment', ?, 'completed', ?)
            ''', (ref_id, target_user_id, delta, desc))

        cur.execute('''
            INSERT INTO fund_adjustments (admin_user, amount, adjustment_type, target_user_id, target_username, note)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_user, amount, adjustment_type, target_user_id, target_username, note[:240]))

        log_admin_audit('funds_' + adjustment_type, target=target_username or 'shop', detail=f'₱{amount:.2f} ({note[:60]})', cursor=cur)
        conn.commit()

        cur.execute("SELECT COALESCE(SUM(amount), 0.0) AS total FROM fund_adjustments WHERE adjustment_type = 'add'")
        added = float(cur.fetchone()['total'] or 0)
        cur.execute("SELECT COALESCE(SUM(amount), 0.0) AS total FROM fund_adjustments WHERE adjustment_type = 'remove'")
        removed = float(cur.fetchone()['total'] or 0)
        balance = round(added - removed, 2)

        msg = f"₱{amount:.2f} {'added to' if adjustment_type == 'add' else 'removed from'} @{target_username}!" if target_username else 'Funds updated.'
        return jsonify({'success': True, 'message': msg, 'balance': balance})
    finally:
        conn.close()


@admin_bp.route('/api/admin/revenue', methods=['GET'])
@admin_required
def admin_revenue():
    from_str = request.args.get('from', '').strip()
    to_str = request.args.get('to', '').strip()
    interval = request.args.get('interval', 'daily').strip()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('SELECT price, product_name, created_at FROM orders ORDER BY created_at ASC')
        all_orders = [dict(row) for row in cur.fetchall()]
        try:
            cur.execute("SELECT amount, category, note, occurred_on FROM ledger_entries WHERE entry_type IN ('sale', 'direct_sale')")
            for le in cur.fetchall():
                le_d = dict(le)
                all_orders.append({
                    'price': float(le_d.get('amount') or 0),
                    'product_name': le_d.get('category') or 'Kova Android',
                    'created_at': f"{str(le_d.get('occurred_on'))[:10]} 12:00:00",
                })
        except Exception:
            pass
    finally:
        conn.close()

    if not from_str or not to_str:
        now = datetime.utcnow()
        last_day = calendar.monthrange(now.year, now.month)[1]
        from_str = from_str or f"{now.year:04d}-{now.month:02d}-01"
        to_str = to_str or f"{now.year:04d}-{now.month:02d}-{last_day:02d}"

    try:
        dt_from = datetime.strptime(from_str, '%Y-%m-%d')
        dt_to = datetime.strptime(to_str, '%Y-%m-%d')
    except Exception:
        dt_from = datetime(2026, 10, 1)
        dt_to = datetime(2026, 10, 31)
        from_str, to_str = '2026-10-01', '2026-10-31'

    period_orders = []
    breakdown = {
        'Source Code': {'name': 'Source Code', 'key': 'source_code', 'icon': 'code', 'sold': 0, 'amount': 0.0},
        'Kova Android': {'name': 'Kova Android', 'key': 'kova_android', 'icon': 'android', 'sold': 0, 'amount': 0.0},
        'Cloud iOS': {'name': 'Cloud iOS', 'key': 'cloud_ios', 'icon': 'apple', 'sold': 0, 'amount': 0.0},
    }

    period_revenue = 0.0
    period_orders_count = 0

    for o in all_orders:
        created_str = str(o['created_at'])[:10]
        try:
            o_dt = datetime.strptime(created_str, '%Y-%m-%d')
        except Exception:
            continue
        if dt_from <= o_dt <= dt_to:
            period_orders.append(o)
            price = float(o['price'] or 0)
            period_revenue += price
            period_orders_count += 1
            cat = _categorize_order(o.get('product_name', ''))
            if cat not in breakdown:
                cat = 'Kova Android'
            breakdown[cat]['sold'] += 1
            breakdown[cat]['amount'] += price

    duration_days = max(1, (dt_to - dt_from).days + 1)
    prev_dt_to = dt_from - timedelta(days=1)
    prev_dt_from = prev_dt_to - timedelta(days=duration_days - 1)
    prev_revenue = 0.0
    for o in all_orders:
        try:
            o_dt = datetime.strptime(str(o['created_at'])[:10], '%Y-%m-%d')
            if prev_dt_from <= o_dt <= prev_dt_to:
                prev_revenue += float(o['price'] or 0)
        except Exception:
            pass

    pct_change = round(((period_revenue - prev_revenue) / prev_revenue) * 100.0, 1) if prev_revenue > 0 else (100.0 if period_revenue > 0 else 0.0)

    chart_points = []
    if interval == 'monthly':
        m_map = {}
        for o in period_orders:
            m_key = str(o['created_at'])[:7]
            m_map[m_key] = m_map.get(m_key, 0.0) + float(o['price'] or 0)
        for m_key in sorted(m_map.keys()):
            try:
                label = datetime.strptime(m_key + '-01', '%Y-%m-%d').strftime('%b %Y')
            except Exception:
                label = m_key
            chart_points.append({'label': label, 'raw': m_key, 'amount': round(m_map[m_key], 2)})
    else:
        day_map = {}
        for o in period_orders:
            d_key = str(o['created_at'])[:10]
            day_map[d_key] = day_map.get(d_key, 0.0) + float(o['price'] or 0)
        curr = dt_from
        while curr <= dt_to:
            d_key = curr.strftime('%Y-%m-%d')
            chart_points.append({
                'label': curr.strftime('%b %d').replace(' 0', ' '),
                'raw': d_key,
                'amount': round(day_map.get(d_key, 0.0), 2),
            })
            curr += timedelta(days=1)

    max_amount = max([p['amount'] for p in chart_points] + [100.0])

    months = {}
    for o in all_orders:
        m_key = str(o['created_at'])[:7]
        if m_key not in months:
            months[m_key] = {'month': m_key, 'revenue': 0.0, 'orders': 0}
        months[m_key]['revenue'] += float(o['price'] or 0)
        months[m_key]['orders'] += 1

    months_list = [
        {'month': months[k]['month'], 'revenue': round(months[k]['revenue'], 2), 'orders': months[k]['orders']}
        for k in sorted(months.keys(), reverse=True)
    ]

    return jsonify({
        'total_revenue': round(period_revenue, 2),
        'total_orders': period_orders_count,
        'from_date': from_str,
        'to_date': to_str,
        'interval': interval,
        'pct_change': pct_change,
        'is_increase': pct_change >= 0,
        'max_amount': max_amount,
        'chart_points': chart_points,
        'breakdown': list(breakdown.values()),
        'months': months_list,
    })


# ── SECURITY, IP BLOCKS & AUDIT LOG ──

@admin_bp.route('/api/admin/security', methods=['GET'])
@admin_required
def admin_security():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT id, ip, kind, path, detail, created_at
            FROM security_events
            ORDER BY id DESC
            LIMIT 80
        ''')
        events = [dict(row) for row in cur.fetchall()]
        for ev in events:
            ev['created_at'] = str(ev.get('created_at') or '')

        if is_postgres():
            cur.execute("SELECT kind, COUNT(*) AS c FROM security_events WHERE created_at >= NOW() - INTERVAL '30 days' GROUP BY kind")
        else:
            cur.execute("SELECT kind, COUNT(*) AS c FROM security_events WHERE created_at >= datetime('now', '-30 days') GROUP BY kind")
        counts = {row['kind']: int(row['c']) for row in cur.fetchall()}

        cur.execute('SELECT id, ip, reason, blocked_by, created_at FROM blocked_ips ORDER BY id DESC LIMIT 100')
        blocked = []
        for r in cur.fetchall():
            d = dict(r)
            d['created_at'] = str(d.get('created_at') or '')
            blocked.append(d)

        cur.execute('SELECT id, admin_user, action, target, detail, ip, created_at FROM admin_audit_logs ORDER BY id DESC LIMIT 100')
        audit_logs = []
        for r in cur.fetchall():
            d = dict(r)
            d['created_at'] = str(d.get('created_at') or '')
            audit_logs.append(d)

        return jsonify({
            'events': events,
            'counts': counts,
            'blocked_ips': blocked,
            'audit_logs': audit_logs,
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/security/block-ip', methods=['POST'])
@admin_required
def admin_block_ip():
    data = request.get_json() or {}
    ip = (data.get('ip') or '').strip()[:80]
    reason = (data.get('reason') or 'Blocked by admin').strip()[:200]
    if not ip:
        return jsonify({'error': 'IP address is required.'}), 400
    if ip in ('127.0.0.1', '::1', 'localhost') or ip == client_ip():
        return jsonify({'error': 'Cannot block localhost or your own active IP address.'}), 400

    admin_user = session.get('username') or 'admin'
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM blocked_ips WHERE ip = ?', (ip,))
        if cursor_row := cur.fetchone():
            return jsonify({'error': f'{ip} is already blocked.'}), 409
        cur.execute('INSERT INTO blocked_ips (ip, reason, blocked_by) VALUES (?, ?, ?)', (ip, reason, admin_user))
        log_admin_audit('ip_block', target=ip, detail=reason, cursor=cur)
        conn.commit()
        invalidate_blocked_ips_cache()
        return jsonify({'success': True, 'message': f'Blocked IP {ip}.'}), 201
    finally:
        conn.close()


@admin_bp.route('/api/admin/security/block-ip/<int:block_id>', methods=['DELETE'])
@admin_required
def admin_unblock_ip(block_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('SELECT ip FROM blocked_ips WHERE id = ?', (block_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Blocked IP record not found.'}), 404
        cur.execute('DELETE FROM blocked_ips WHERE id = ?', (block_id,))
        log_admin_audit('ip_unblock', target=row['ip'], cursor=cur)
        conn.commit()
        invalidate_blocked_ips_cache()
        return jsonify({'success': True, 'message': f"Unblocked {row['ip']}."})
    finally:
        conn.close()


# ── REFERRALS ADMIN ──

@admin_bp.route('/api/admin/referrals', methods=['GET'])
@admin_required
def admin_referrals():
    conn = get_db()
    cursor = conn.cursor()
    try:
        enabled = get_setting(cursor, 'referral_enabled', '1') == '1'
        try:
            percent = float(get_setting(cursor, 'referral_percent', '5') or 5)
        except Exception:
            percent = 5.0

        cursor.execute('SELECT COALESCE(SUM(reward), 0.0) AS total_paid FROM referral_rewards')
        total_paid = float((cursor.fetchone() or {}).get('total_paid') or 0.0)

        cursor.execute('SELECT COUNT(*) AS cnt FROM users WHERE referred_by IS NOT NULL')
        referred_users_count = int(cursor.fetchone()['cnt'] or 0)

        cursor.execute('SELECT COUNT(DISTINCT referred_by) AS cnt FROM users WHERE referred_by IS NOT NULL')
        active_referrers_count = int(cursor.fetchone()['cnt'] or 0)

        cursor.execute('''
            SELECT u.id, u.username, u.referral_code,
                   COALESCE(u.referral_earnings, 0.0) AS earned,
                   (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.id) AS referred_count
            FROM users u
            WHERE COALESCE(u.referral_earnings, 0.0) > 0
               OR EXISTS (SELECT 1 FROM users r WHERE r.referred_by = u.id)
            ORDER BY earned DESC, referred_count DESC
            LIMIT 50
        ''')
        top_referrers = [
            {
                'id': r['id'],
                'username': r['username'],
                'code': r['referral_code'],
                'referred_count': int(r['referred_count'] or 0),
                'earned': round(float(r['earned'] or 0.0), 2),
            }
            for r in cursor.fetchall()
        ]

        cursor.execute('''
            SELECT rr.id, rr.order_id, rr.order_amount, rr.percent, rr.reward, rr.created_at,
                   COALESCE(u1.username, 'Unknown') AS referrer_username,
                   COALESCE(u2.username, 'Unknown') AS referred_username
            FROM referral_rewards rr
            LEFT JOIN users u1 ON rr.referrer_id = u1.id
            LEFT JOIN users u2 ON rr.referred_user_id = u2.id
            ORDER BY rr.id DESC
            LIMIT 100
        ''')
        rewards = [
            {
                'id': r['id'],
                'order_id': r['order_id'],
                'referrer_username': r['referrer_username'],
                'referred_username': r['referred_username'],
                'order_amount': float(r['order_amount'] or 0),
                'percent': float(r['percent'] or 0),
                'reward': float(r['reward'] or 0),
                'created_at': str(r['created_at'] or ''),
            }
            for r in cursor.fetchall()
        ]

        return jsonify({
            'settings': {'enabled': enabled, 'percent': percent},
            'totals': {
                'total_paid': round(total_paid, 2),
                'referred_users': referred_users_count,
                'active_referrers': active_referrers_count,
            },
            'top_referrers': top_referrers,
            'rewards': rewards,
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/referrals/settings', methods=['POST'])
@admin_required
def admin_referrals_settings():
    data = request.get_json() or {}
    enabled = bool(data.get('enabled', True))
    try:
        percent = float(data.get('percent', 5))
    except (TypeError, ValueError):
        return jsonify({'error': 'Commission percent must be a valid number.'}), 400

    if percent < 0 or percent > 50:
        return jsonify({'error': 'Commission percent must be between 0 and 50.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        set_setting(cursor, 'referral_enabled', '1' if enabled else '0')
        set_setting(cursor, 'referral_percent', f"{percent:g}")
        log_admin_audit('referral_settings', detail=f'enabled={enabled}, percent={percent:g}%', cursor=cursor)
        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Referral settings saved.',
            'settings': {'enabled': enabled, 'percent': percent},
        })
    finally:
        conn.close()


# ── CATALOG, PRODUCTS & IMAGE UPLOAD ──

@admin_bp.route('/api/admin/catalog', methods=['GET'])
@admin_required
def admin_get_catalog():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, title, category, platform, image_url, description, is_active FROM catalog_items ORDER BY id ASC')
        catalog = []
        for item in cursor.fetchall():
            cursor.execute('''
                SELECT p.id, p.catalog_id, p.name, p.duration, p.price, p.badge, p.features, p.is_active,
                       (SELECT COUNT(*) FROM license_keys k WHERE k.product_id = p.id AND k.is_used = 0) AS stock,
                       (SELECT COUNT(*) FROM orders o WHERE o.product_id = p.id) AS sold
                FROM products p
                WHERE p.catalog_id = ?
                ORDER BY p.price ASC, p.id ASC
            ''', (item['id'],))
            tiers = []
            for pr in cursor.fetchall():
                try:
                    feat = json.loads(pr['features']) if pr['features'] else []
                except Exception:
                    feat = []
                tiers.append({
                    'id': pr['id'],
                    'catalog_id': pr['catalog_id'],
                    'name': pr['name'],
                    'duration': pr['duration'],
                    'price': float(pr['price']),
                    'badge': pr['badge'] or '',
                    'features': feat if isinstance(feat, list) else [],
                    'is_active': int(pr['is_active']) if pr['is_active'] is not None else 1,
                    'stock': int(pr['stock'] or 0),
                    'sold': int(pr['sold'] or 0),
                })
            catalog.append({
                'id': item['id'],
                'title': item['title'],
                'category': item['category'],
                'platform': item['platform'],
                'image_url': item['image_url'],
                'description': item['description'] or '',
                'is_active': int(item['is_active']) if item['is_active'] is not None else 1,
                'tiers': tiers,
            })
        return jsonify({'catalog': catalog})
    finally:
        conn.close()


@admin_bp.route('/api/admin/catalog', methods=['POST'])
@admin_required
def admin_create_catalog():
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'Product title is required.'}), 400

    category = (data.get('category') or 'GAMES').strip().upper() or 'GAMES'
    platform = (data.get('platform') or 'ANDROID').strip().upper() or 'ANDROID'
    image_url = (data.get('image_url') or '/static/images/product1.jpg').strip()
    description = (data.get('description') or '').strip()
    is_active = 1 if int(data.get('is_active', 1)) else 0

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO catalog_items (title, category, platform, image_url, description, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, category, platform, image_url, description, is_active))
        new_id = cursor.lastrowid
        log_admin_audit('catalog_create', target=title, cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'id': new_id, 'message': f'Product "{title}" created.'}), 201
    finally:
        conn.close()


@admin_bp.route('/api/admin/catalog/<int:item_id>', methods=['PUT'])
@admin_required
def admin_update_catalog(item_id):
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'Product title is required.'}), 400

    category = (data.get('category') or 'GAMES').strip().upper() or 'GAMES'
    platform = (data.get('platform') or 'ANDROID').strip().upper() or 'ANDROID'
    image_url = (data.get('image_url') or '/static/images/product1.jpg').strip()
    description = (data.get('description') or '').strip()
    is_active = 1 if int(data.get('is_active', 1)) else 0

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id FROM catalog_items WHERE id = ?', (item_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Catalog item not found.'}), 404

        cursor.execute('''
            UPDATE catalog_items
            SET title = ?, category = ?, platform = ?, image_url = ?, description = ?, is_active = ?
            WHERE id = ?
        ''', (title, category, platform, image_url, description, is_active, item_id))
        log_admin_audit('catalog_update', target=title, detail=f'active={is_active}', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'message': f'Product "{title}" updated.'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/catalog/<int:item_id>', methods=['DELETE'])
@admin_required
def admin_delete_catalog(item_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, title FROM catalog_items WHERE id = ?', (item_id,))
        item = cursor.fetchone()
        if not item:
            return jsonify({'error': 'Catalog item not found.'}), 404

        cursor.execute('SELECT id FROM products WHERE catalog_id = ?', (item_id,))
        tier_ids = [r['id'] for r in cursor.fetchall()]

        has_refs = False
        if tier_ids:
            placeholders = ', '.join(['?'] * len(tier_ids))
            cursor.execute(f'SELECT COUNT(*) AS c FROM orders WHERE product_id IN ({placeholders})', tuple(tier_ids))
            if int(cursor.fetchone()['c'] or 0) > 0:
                has_refs = True
            else:
                cursor.execute(f'SELECT COUNT(*) AS c FROM license_keys WHERE product_id IN ({placeholders})', tuple(tier_ids))
                if int(cursor.fetchone()['c'] or 0) > 0:
                    has_refs = True

        if has_refs:
            cursor.execute('UPDATE catalog_items SET is_active = 0 WHERE id = ?', (item_id,))
            cursor.execute('UPDATE products SET is_active = 0 WHERE catalog_id = ?', (item_id,))
            log_admin_audit('catalog_archive', target=item['title'], cursor=cursor)
            conn.commit()
            return jsonify({'success': True, 'soft': True, 'message': f'"{item["title"]}" has existing orders or keys, so it was archived.'})

        cursor.execute('DELETE FROM products WHERE catalog_id = ?', (item_id,))
        cursor.execute('DELETE FROM catalog_items WHERE id = ?', (item_id,))
        log_admin_audit('catalog_delete', target=item['title'], cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'soft': False, 'message': f'"{item["title"]}" deleted.'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/products', methods=['POST'])
@admin_required
def admin_create_product():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    duration = (data.get('duration') or '').strip()
    badge = (data.get('badge') or '').strip()
    is_active = 1 if int(data.get('is_active', 1)) else 0

    try:
        catalog_id = int(data.get('catalog_id'))
        price = float(data.get('price'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Valid catalog_id and price are required.'}), 400

    if not name or not duration or price <= 0:
        return jsonify({'error': 'Tier name, duration, and a positive price are required.'}), 400

    features_json = _parse_features_input(data.get('features', []))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id FROM catalog_items WHERE id = ?', (catalog_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Parent catalog item not found.'}), 404

        cursor.execute('''
            INSERT INTO products (catalog_id, name, duration, price, badge, features, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (catalog_id, name, duration, price, badge, features_json, is_active))
        new_id = cursor.lastrowid
        log_admin_audit('tier_create', target=name, detail=f'₱{price:.2f} ({duration})', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'id': new_id, 'message': f'Tier "{name}" added.'}), 201
    finally:
        conn.close()


@admin_bp.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@admin_required
def admin_update_product(product_id):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    duration = (data.get('duration') or '').strip()
    badge = (data.get('badge') or '').strip()
    is_active = 1 if int(data.get('is_active', 1)) else 0

    try:
        price = float(data.get('price'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Price must be a valid number.'}), 400

    if not name or not duration or price <= 0:
        return jsonify({'error': 'Tier name, duration, and a positive price are required.'}), 400

    features_json = _parse_features_input(data.get('features', []))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, catalog_id FROM products WHERE id = ?', (product_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({'error': 'Product tier not found.'}), 404

        catalog_id = int(data.get('catalog_id') or existing['catalog_id'])
        cursor.execute('''
            UPDATE products
            SET catalog_id = ?, name = ?, duration = ?, price = ?, badge = ?, features = ?, is_active = ?
            WHERE id = ?
        ''', (catalog_id, name, duration, price, badge, features_json, is_active, product_id))
        log_admin_audit('tier_update', target=name, detail=f'₱{price:.2f} ({duration}) active={is_active}', cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'message': f'Tier "{name}" updated.'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@admin_required
def admin_delete_product(product_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, name FROM products WHERE id = ?', (product_id,))
        pr = cursor.fetchone()
        if not pr:
            return jsonify({'error': 'Product tier not found.'}), 404

        cursor.execute('SELECT COUNT(*) AS c FROM orders WHERE product_id = ?', (product_id,))
        ord_cnt = int(cursor.fetchone()['c'] or 0)
        cursor.execute('SELECT COUNT(*) AS c FROM license_keys WHERE product_id = ?', (product_id,))
        key_cnt = int(cursor.fetchone()['c'] or 0)

        if ord_cnt > 0 or key_cnt > 0:
            cursor.execute('UPDATE products SET is_active = 0 WHERE id = ?', (product_id,))
            log_admin_audit('tier_archive', target=pr['name'], cursor=cursor)
            conn.commit()
            return jsonify({'success': True, 'soft': True, 'message': f'Tier "{pr["name"]}" has orders or keys, so it was archived.'})

        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        log_admin_audit('tier_delete', target=pr['name'], cursor=cursor)
        conn.commit()
        return jsonify({'success': True, 'soft': False, 'message': f'Tier "{pr["name"]}" deleted.'})
    finally:
        conn.close()


@admin_bp.route('/api/admin/upload-image', methods=['POST'])
@admin_required
def admin_upload_image():
    if request.content_length and request.content_length > MAX_IMAGE_BYTES + 4096:
        return jsonify({'error': 'Image exceeds 5MB limit.'}), 400

    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No image file uploaded.'}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_IMAGE_EXTS:
        return jsonify({'error': 'Allowed formats: png, jpg, jpeg, webp, gif.'}), 400

    data_bytes = file.read()
    if len(data_bytes) > MAX_IMAGE_BYTES:
        return jsonify({'error': 'Image exceeds 5MB limit.'}), 400

    # Verify magic bytes so non-image scripts cannot be disguised with an image extension
    valid_sig = (
        data_bytes.startswith(b'\x89PNG\r\n\x1a\n')
        or data_bytes.startswith(b'\xff\xd8\xff')
        or data_bytes.startswith((b'GIF87a', b'GIF89a'))
        or (data_bytes.startswith(b'RIFF') and data_bytes[8:12] == b'WEBP')
    )
    if not valid_sig:
        return jsonify({'error': 'Uploaded file is not a valid image.'}), 400

    upload_dir = os.path.join(current_app.root_path, 'static', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    out_name = f"{uuid.uuid4().hex}.{ext}"
    with open(os.path.join(upload_dir, out_name), 'wb') as f:
        f.write(data_bytes)

    log_admin_audit('image_upload', target=out_name)
    return jsonify({'success': True, 'url': f'/static/uploads/{out_name}'})


# ── ORDERS EXPLORER & DETAIL ──

@admin_bp.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_list_orders():
    search = (request.args.get('search') or '').strip()
    product_id = (request.args.get('product_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()

    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(100, max(1, int(request.args.get('per_page', 25))))
    except ValueError:
        per_page = 25

    where = ['1=1']
    params = []

    if search:
        like_q = f"%{search.lower()}%"
        where.append("(LOWER(o.order_id) LIKE ? OR LOWER(COALESCE(u.username, '')) LIKE ? OR LOWER(COALESCE(u.email, '')) LIKE ? OR LOWER(o.license_key) LIKE ? OR LOWER(COALESCE(o.voucher_code, '')) LIKE ?)")
        params.extend([like_q, like_q, like_q, like_q, like_q])

    if product_id and product_id != 'all' and product_id.isdigit():
        where.append('o.product_id = ?')
        params.append(int(product_id))

    date_expr = "SUBSTRING(CAST(o.created_at AS TEXT), 1, 10)" if is_postgres() else "substr(o.created_at, 1, 10)"
    if date_from:
        where.append(f"{date_expr} >= ?")
        params.append(date_from[:10])
    if date_to:
        where.append(f"{date_expr} <= ?")
        params.append(date_to[:10])

    where_sql = ' AND '.join(where)
    offset = (page - 1) * per_page

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(f'''
            SELECT COUNT(*) AS total, COALESCE(SUM(o.price), 0.0) AS revenue_sum
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE {where_sql}
        ''', tuple(params))
        agg = cursor.fetchone()
        total = int(agg['total'] or 0) if agg else 0
        revenue_sum = round(float(agg['revenue_sum'] or 0.0), 2) if agg else 0.0
        pages = max(1, (total + per_page - 1) // per_page)

        cursor.execute(f'''
            SELECT o.id, o.order_id, o.user_id, o.product_id, o.product_name, o.price, o.license_key,
                   o.voucher_code, o.discount_amount, o.created_at,
                   COALESCE(u.username, 'User #' || o.user_id) AS username,
                   COALESCE(u.email, '') AS email
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE {where_sql}
            ORDER BY o.id DESC
            LIMIT ? OFFSET ?
        ''', tuple(params + [per_page, offset]))

        orders = []
        for r in cursor.fetchall():
            orders.append({
                'id': r['id'],
                'order_id': r['order_id'],
                'user_id': r['user_id'],
                'username': r['username'],
                'email': r['email'],
                'product_id': r['product_id'],
                'product_name': r['product_name'],
                'price': float(r['price'] or 0),
                'license_key': r['license_key'],
                'voucher_code': r['voucher_code'] or '',
                'discount_amount': float(r['discount_amount'] or 0),
                'created_at': str(r['created_at'] or ''),
            })

        return jsonify({
            'orders': orders,
            'total': total,
            'page': page,
            'pages': pages,
            'per_page': per_page,
            'revenue_sum': revenue_sum,
        })
    finally:
        conn.close()


@admin_bp.route('/api/admin/orders/<order_id>', methods=['GET'])
@admin_required
def admin_order_detail(order_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT o.id, o.order_id, o.user_id, o.product_id, o.product_name, o.price, o.license_key,
                   o.voucher_code, o.discount_amount, o.created_at
            FROM orders o
            WHERE o.order_id = ?
        ''', (order_id,))
        order = cursor.fetchone()
        if not order:
            return jsonify({'error': 'Order not found.'}), 404

        cursor.execute('SELECT id, username, email, balance, created_at FROM users WHERE id = ?', (order['user_id'],))
        buyer_row = cursor.fetchone()

        cursor.execute('SELECT COUNT(*) AS cnt, COALESCE(SUM(price), 0.0) AS spent FROM orders WHERE user_id = ?', (order['user_id'],))
        buyer_stats = cursor.fetchone()

        buyer = None
        if buyer_row:
            buyer = {
                'id': buyer_row['id'],
                'username': buyer_row['username'],
                'email': buyer_row['email'],
                'balance': round(float(buyer_row['balance'] or 0), 2),
                'created_at': str(buyer_row['created_at'] or ''),
                'total_orders': int(buyer_stats['cnt'] or 0) if buyer_stats else 0,
                'total_spent': round(float(buyer_stats['spent'] or 0), 2) if buyer_stats else 0.0,
            }

        cursor.execute('''
            SELECT id, is_used, assigned_to_user_id, used_at, created_at
            FROM license_keys
            WHERE TRIM(license_key) = TRIM(?)
            ORDER BY id DESC
            LIMIT 1
        ''', (order['license_key'],))
        key_row = cursor.fetchone()
        key_info = None
        if key_row:
            key_info = {
                'id': key_row['id'],
                'is_used': int(key_row['is_used'] or 0),
                'assigned_to_user_id': key_row['assigned_to_user_id'],
                'used_at': str(key_row['used_at'] or ''),
                'created_at': str(key_row['created_at'] or ''),
            }

        cursor.execute('''
            SELECT rr.reward, rr.percent, rr.referrer_id, COALESCE(u.username, 'Unknown') AS referrer_username
            FROM referral_rewards rr
            LEFT JOIN users u ON rr.referrer_id = u.id
            WHERE rr.order_id = ?
            LIMIT 1
        ''', (order['order_id'],))
        ref_row = cursor.fetchone()
        referral_info = None
        if ref_row:
            referral_info = {
                'referrer_id': ref_row['referrer_id'],
                'referrer_username': ref_row['referrer_username'],
                'percent': float(ref_row['percent'] or 0),
                'reward': float(ref_row['reward'] or 0),
            }

        return jsonify({
            'order': {
                'id': order['id'],
                'order_id': order['order_id'],
                'product_id': order['product_id'],
                'product_name': order['product_name'],
                'price': float(order['price'] or 0),
                'license_key': order['license_key'],
                'voucher_code': order['voucher_code'] or '',
                'discount_amount': float(order['discount_amount'] or 0),
                'created_at': str(order['created_at'] or ''),
            },
            'buyer': buyer,
            'key_status': key_info,
            'referral': referral_info,
        })
    finally:
        conn.close()
