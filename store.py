import json
import uuid
from datetime import datetime
from flask import Blueprint, current_app, jsonify, request, session

from core.config import APP_URL, PAYMONGO_SECRET_KEY, get_setting
from core.security import client_ip, log_security, login_required, recent_event_count
from database import generate_referral_code, get_db
from routes.wallet import _credit_deposit_once, _fetch_paymongo_session

store_bp = Blueprint('store', __name__)


def is_lifetime_product(product_row) -> bool:
    dur = str(product_row['duration'] or '').lower()
    name = str(product_row['name'] or '').lower()
    return 'lifetime' in dur or 'lifetime' in name


def _validate_voucher_for_purchase(cursor, raw_code: str, user_id: int, product_row) -> tuple[dict | None, str | None, int]:
    """Validate voucher against product & user. Returns (voucher_info, error_msg, http_status)."""
    code = (raw_code or '').strip().upper()
    if not code:
        return None, 'Enter a voucher code.', 400

    cursor.execute('''
        SELECT id, code, discount_percent, tier_scope, max_uses, used_count, per_user_limit, expires_at, is_active
        FROM vouchers
        WHERE UPPER(code) = ?
    ''', (code,))
    v = cursor.fetchone()
    if not v:
        log_security('voucher_fail', f'unknown code {code[:20]}')
        return None, 'Invalid voucher code.', 404

    if not int(v['is_active'] or 0):
        return None, 'This voucher is no longer active.', 400

    exp = (v['expires_at'] or '').strip()
    if exp:
        today_str = datetime.utcnow().strftime('%Y-%m-%d')
        if exp[:10] < today_str:
            return None, 'This voucher has expired.', 400

    max_uses = int(v['max_uses'] or 0)
    used_count = int(v['used_count'] or 0)
    if max_uses > 0 and used_count >= max_uses:
        return None, 'This voucher has reached its maximum redemptions.', 400

    per_user = int(v['per_user_limit'] or 0)
    if per_user > 0:
        cursor.execute(
            'SELECT COUNT(*) AS c FROM voucher_usages WHERE voucher_id = ? AND user_id = ?',
            (v['id'], user_id)
        )
        u_row = cursor.fetchone()
        u_cnt = int(u_row['c'] if isinstance(u_row, dict) or hasattr(u_row, 'keys') else u_row[0])
        if u_cnt >= per_user:
            return None, 'You have already used this voucher.', 400

    scope = (v['tier_scope'] or 'lifetime').lower()
    if scope == 'lifetime' and not is_lifetime_product(product_row):
        return None, 'This voucher is valid only for Lifetime keys.', 400

    orig_price = float(product_row['price'])
    pct = int(v['discount_percent'])
    discount_amt = round(orig_price * (pct / 100.0), 2)
    final_price = max(0.0, round(orig_price - discount_amt, 2))

    return {
        'id': v['id'],
        'code': v['code'],
        'discount_percent': pct,
        'tier_scope': scope,
        'original_price': orig_price,
        'discount_amount': discount_amt,
        'final_price': final_price,
    }, None, 200


@store_bp.route('/api/products', methods=['GET'])
def list_products():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT p.id, p.name, p.duration, p.price, p.badge, p.features,
                   (SELECT COUNT(*) FROM license_keys WHERE product_id = p.id AND is_used = 0) as in_stock
            FROM products p
            WHERE p.is_active = 1
            ORDER BY p.price ASC
        ''')
        products = []
        for row in cursor.fetchall():
            try:
                features_list = json.loads(row['features'])
            except Exception:
                features_list = []
            products.append({
                'id': row['id'],
                'name': row['name'],
                'duration': row['duration'],
                'price': float(row['price']),
                'badge': row['badge'],
                'features': features_list,
                'stock': row['in_stock'],
            })
        return jsonify({'products': products})
    finally:
        conn.close()


@store_bp.route('/api/catalog', methods=['GET'])
def get_catalog():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, title, category, platform, image_url, description FROM catalog_items WHERE is_active = 1 ORDER BY id ASC')
        items = cursor.fetchall()
        catalog = []
        for item in items:
            cursor.execute('''
                SELECT p.id, p.name, p.duration, p.price, p.badge, p.features,
                       (SELECT COUNT(*) FROM license_keys WHERE product_id = p.id AND is_used = 0) as in_stock
                FROM products p
                WHERE p.catalog_id = ? AND p.is_active = 1
                ORDER BY p.price ASC
            ''', (item['id'],))
            options = []
            min_p = 999999.0
            max_p = 0.0
            total_stock = 0

            for pr in cursor.fetchall():
                price = float(pr['price'])
                if price < min_p:
                    min_p = price
                if price > max_p:
                    max_p = price
                stock = int(pr['in_stock'] or 0)
                total_stock += stock
                try:
                    features_list = json.loads(pr['features'])
                except Exception:
                    features_list = []
                options.append({
                    'id': pr['id'],
                    'name': pr['name'],
                    'duration': pr['duration'],
                    'price': price,
                    'badge': pr['badge'],
                    'features': features_list,
                    'stock': stock,
                })

            catalog.append({
                'id': item['id'],
                'title': item['title'],
                'category': item['category'],
                'platform': item['platform'],
                'image_url': item['image_url'],
                'description': item['description'],
                'options_count': len(options),
                'min_price': min_p if min_p != 999999.0 else 70.0,
                'max_price': max_p if max_p != 0.0 else 700.0,
                'total_stock': total_stock,
                'options': options,
            })
        return jsonify({'catalog': catalog})
    finally:
        conn.close()


@store_bp.route('/api/catalog/<int:item_id>', methods=['GET'])
def get_catalog_item(item_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, title, category, platform, image_url, description FROM catalog_items WHERE id = ? AND is_active = 1', (item_id,))
        item = cursor.fetchone()
        if not item:
            return jsonify({'error': 'Product not found'}), 404

        cursor.execute('''
            SELECT p.id, p.name, p.duration, p.price, p.badge, p.features,
                   (SELECT COUNT(*) FROM license_keys WHERE product_id = p.id AND is_used = 0) as in_stock
            FROM products p
            WHERE p.catalog_id = ? AND p.is_active = 1
            ORDER BY p.price ASC
        ''', (item['id'],))
        options = []
        total_stock = 0
        for pr in cursor.fetchall():
            stock = int(pr['in_stock'] or 0)
            total_stock += stock
            try:
                features_list = json.loads(pr['features'])
            except Exception:
                features_list = []
            options.append({
                'id': pr['id'],
                'name': pr['name'],
                'duration': pr['duration'],
                'price': float(pr['price']),
                'badge': pr['badge'],
                'features': features_list,
                'stock': stock,
            })

        return jsonify({
            'product': {
                'id': item['id'],
                'title': item['title'],
                'category': item['category'],
                'platform': item['platform'],
                'image_url': item['image_url'],
                'description': item['description'],
                'total_stock': total_stock,
                'options': options,
            }
        })
    finally:
        conn.close()


@store_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT reference_id, amount
            FROM transactions
            WHERE user_id = ? AND status = 'pending' AND reference_id LIKE 'cs_%'
        ''', (user_id,))
        pending_txs = cursor.fetchall()

        if pending_txs and PAYMONGO_SECRET_KEY and 'demo_key' not in PAYMONGO_SECRET_KEY:
            for ptx in pending_txs:
                sid = ptx['reference_id']
                try:
                    pm_data = _fetch_paymongo_session(sid)
                    if pm_data:
                        attrs = pm_data.get('attributes', {})
                        payments = attrs.get('payments', [])
                        is_paid = (payments and payments[0].get('attributes', {}).get('status') == 'paid') or attrs.get('status') == 'paid'
                        if is_paid:
                            amt = float(ptx['amount'])
                            _credit_deposit_once(cursor, sid, user_id, amt, f"PayMongo Paid via GCash/Card (₱{amt:.2f})")
                            conn.commit()
                except Exception:
                    pass

        cursor.execute('SELECT username, email, balance, role, referral_code, referral_earnings FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        ref_code = user['referral_code'] if user else ''
        if user and not ref_code:
            ref_code = generate_referral_code(cursor)
            cursor.execute('UPDATE users SET referral_code = ? WHERE id = ?', (ref_code, user_id))
            conn.commit()

        ref_enabled = get_setting(cursor, 'referral_enabled', '1') == '1'
        try:
            ref_percent = float(get_setting(cursor, 'referral_percent', '5') or 5)
        except Exception:
            ref_percent = 5.0

        cursor.execute('SELECT COUNT(*) as total_orders, COALESCE(SUM(price), 0.0) as credits_spent FROM orders WHERE user_id = ?', (user_id,))
        order_data = cursor.fetchone()

        cursor.execute('SELECT COUNT(*) as registered_users FROM users')
        registered_users = int(cursor.fetchone()['registered_users'] or 0)

        cursor.execute('SELECT COUNT(*) as total_products FROM catalog_items WHERE is_active = 1')
        total_products = int(cursor.fetchone()['total_products'] or 0)

        cursor.execute('SELECT COUNT(*) as global_orders FROM orders')
        global_orders = int(cursor.fetchone()['global_orders'] or 0)

        cursor.execute('''
            SELECT order_id, product_name, price, license_key, voucher_code, discount_amount, created_at
            FROM orders
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        ''', (user_id,))
        recent_orders = [dict(r) for r in cursor.fetchall()]

        cursor.execute('''
            SELECT reference_id, type, amount, status, description, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        ''', (user_id,))
        recent_txs = [dict(r) for r in cursor.fetchall()]

        return jsonify({
            'username': user['username'],
            'email': user['email'],
            'balance': float(user['balance']),
            'role': user['role'],
            'referral_code': ref_code or '',
            'referral_earnings': float(user['referral_earnings'] or 0.0),
            'referral_enabled': ref_enabled,
            'referral_percent': ref_percent,
            'total_orders': int(order_data['total_orders'] or 0),
            'credits_spent': float(order_data['credits_spent'] or 0.0),
            'total_keys': int(order_data['total_orders'] or 0),
            'registered_users': registered_users,
            'total_products': total_products,
            'global_orders': global_orders,
            'recent_orders': recent_orders,
            'recent_transactions': recent_txs,
        })
    finally:
        conn.close()


@store_bp.route('/api/voucher/validate', methods=['POST'])
@login_required
def validate_voucher():
    ip = client_ip()
    if recent_event_count('voucher_fail', 600, ip=ip) >= 12:
        return jsonify({'error': 'Too many invalid voucher attempts. Try again in a few minutes.'}), 429

    data = request.get_json() or {}
    code = (data.get('code') or '').strip().upper()
    product_id = data.get('product_id')

    if not code or not product_id:
        return jsonify({'error': 'Voucher code and selected tier are required.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, name, duration, price FROM products WHERE id = ? AND is_active = 1', (product_id,))
        product = cursor.fetchone()
        if not product:
            return jsonify({'error': 'Selected tier does not exist.'}), 404

        info, err, status = _validate_voucher_for_purchase(cursor, code, int(session['user_id']), product)
        if err:
            return jsonify({'error': err}), status

        return jsonify({
            'valid': True,
            'code': info['code'],
            'discount_percent': info['discount_percent'],
            'tier_scope': info['tier_scope'],
            'original_price': info['original_price'],
            'discount_amount': info['discount_amount'],
            'final_price': info['final_price'],
            'message': f"{info['discount_percent']}% discount applied (-₱{info['discount_amount']:.2f})!",
        })
    finally:
        conn.close()


@store_bp.route('/api/purchase', methods=['POST'])
@login_required
def purchase_product():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    raw_voucher = (data.get('voucher_code') or '').strip().upper()

    if not product_id:
        return jsonify({'error': 'Product ID is required.'}), 400

    if raw_voucher and recent_event_count('voucher_fail', 600) >= 12:
        return jsonify({'error': 'Too many invalid voucher attempts. Try again shortly.'}), 429

    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT id, username, balance FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        cursor.execute('SELECT id, name, duration, price FROM products WHERE id = ? AND is_active = 1', (product_id,))
        product = cursor.fetchone()
        if not product:
            return jsonify({'error': 'Selected tier does not exist.'}), 404

        original_price = float(product['price'])
        final_price = original_price
        discount_amount = 0.0
        voucher_info = None

        if raw_voucher:
            voucher_info, v_err, v_status = _validate_voucher_for_purchase(cursor, raw_voucher, user_id, product)
            if v_err:
                return jsonify({'error': v_err}), v_status
            final_price = voucher_info['final_price']
            discount_amount = voucher_info['discount_amount']

        user_balance = float(user['balance'])
        if user_balance < final_price:
            needed = round(final_price - user_balance, 2)
            return jsonify({
                'error': f'Insufficient balance! You need ₱{needed:.2f} more.',
                'code': 'INSUFFICIENT_FUNDS',
                'current_balance': user_balance,
                'price': final_price,
                'needed': needed,
            }), 400

        # 1. Atomically reserve voucher use if provided
        if voucher_info:
            cursor.execute('''
                UPDATE vouchers
                SET used_count = used_count + 1
                WHERE id = ? AND is_active = 1 AND (max_uses = 0 OR used_count < max_uses)
            ''', (voucher_info['id'],))
            if cursor.rowcount == 0:
                conn.rollback()
                return jsonify({'error': 'Voucher just reached its usage limit.'}), 400

        # 2. Atomically claim an unused license key (retry up to 3 times on contention)
        delivered_key = None
        for _ in range(3):
            cursor.execute('''
                SELECT id, license_key
                FROM license_keys
                WHERE product_id = ? AND is_used = 0
                ORDER BY id ASC
                LIMIT 1
            ''', (product_id,))
            key_record = cursor.fetchone()
            if not key_record:
                break
            cursor.execute('''
                UPDATE license_keys
                SET is_used = 1, assigned_to_user_id = ?, used_at = CURRENT_TIMESTAMP
                WHERE id = ? AND is_used = 0
            ''', (user_id, key_record['id']))
            if cursor.rowcount == 1:
                delivered_key = key_record['license_key']
                break

        if not delivered_key:
            conn.rollback()
            return jsonify({
                'error': f'{product["name"]} is currently out of stock.',
                'code': 'OUT_OF_STOCK',
            }), 400

        # 3. Atomically deduct user balance
        cursor.execute(
            'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
            (final_price, user_id, final_price - 0.001)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({
                'error': 'Insufficient balance for this purchase.',
                'code': 'INSUFFICIENT_FUNDS',
            }), 400

        # 4. Record order, voucher usage, and transaction
        order_id = f"ORD-{datetime.now().strftime('%y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        applied_code = voucher_info['code'] if voucher_info else None

        cursor.execute('''
            INSERT INTO orders (order_id, user_id, product_id, product_name, price, license_key, voucher_code, discount_amount)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (order_id, user_id, product['id'], product['name'], final_price, delivered_key, applied_code, discount_amount))

        if voucher_info:
            cursor.execute('''
                INSERT INTO voucher_usages (voucher_id, voucher_code, user_id, order_id, original_price, discount_amount, final_price)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (voucher_info['id'], voucher_info['code'], user_id, order_id, original_price, discount_amount, final_price))

        tx_desc = f"Purchased {product['name']} ({product['duration']})"
        if voucher_info:
            tx_desc += f" [Voucher {voucher_info['code']} -{voucher_info['discount_percent']}%]"
        cursor.execute('''
            INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
            VALUES (?, ?, 'purchase', ?, 'completed', ?)
        ''', (order_id, user_id, final_price, tx_desc))

        # 5. Referral commission on net paid amount
        try:
            cursor.execute('SELECT referred_by FROM users WHERE id = ?', (user_id,))
            buyer_ref_row = cursor.fetchone()
            referrer_id = buyer_ref_row['referred_by'] if buyer_ref_row else None
            if referrer_id and int(referrer_id) != user_id and final_price > 0:
                ref_enabled = get_setting(cursor, 'referral_enabled', '1')
                pct = float(get_setting(cursor, 'referral_percent', '5') or 5)
                if ref_enabled == '1' and pct > 0:
                    reward = round(final_price * pct / 100.0, 2)
                    if reward > 0:
                        cursor.execute(
                            'UPDATE users SET balance = balance + ?, referral_earnings = COALESCE(referral_earnings, 0) + ? WHERE id = ?',
                            (reward, reward, referrer_id)
                        )
                        cursor.execute('''
                            INSERT INTO referral_rewards (referrer_id, referred_user_id, order_id, order_amount, percent, reward)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (referrer_id, user_id, order_id, final_price, pct, reward))
                        cursor.execute('''
                            INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
                            VALUES (?, ?, 'referral_bonus', ?, 'completed', ?)
                        ''', (f"REF-{order_id}", referrer_id, reward, f"Referral commission ({pct:g}%) from {user['username']}"))
        except Exception as ref_err:
            current_app.logger.warning(f"Referral credit error on {order_id}: {ref_err}")

        conn.commit()

        cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        new_balance = round(float(cursor.fetchone()['balance'] or 0.0), 2)

        return jsonify({
            'success': True,
            'message': 'Purchase completed! Your license key is ready.',
            'order_id': order_id,
            'product_name': product['name'],
            'duration': product['duration'],
            'license_key': delivered_key,
            'original_price': original_price,
            'discount_amount': discount_amount,
            'final_price': final_price,
            'voucher_code': applied_code,
            'new_balance': new_balance,
        })
    except Exception:
        conn.rollback()
        return jsonify({'error': 'Purchase failed due to a server error.'}), 500
    finally:
        conn.close()


@store_bp.route('/api/user/orders', methods=['GET'])
@login_required
def get_user_orders():
    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT order_id, product_name, price, license_key, voucher_code, discount_amount, created_at
            FROM orders
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user_id,))
        return jsonify({'orders': [dict(r) for r in cursor.fetchall()]})
    finally:
        conn.close()


@store_bp.route('/api/user/transactions', methods=['GET'])
@login_required
def get_user_transactions():
    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT reference_id, type, amount, status, description, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user_id,))
        return jsonify({'transactions': [dict(r) for r in cursor.fetchall()]})
    finally:
        conn.close()


@store_bp.route('/api/referrals', methods=['GET'])
@login_required
def user_referrals():
    user_id = int(session['user_id'])
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, referral_code, referral_earnings FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        code = user['referral_code']
        if not code:
            code = generate_referral_code(cursor)
            cursor.execute('UPDATE users SET referral_code = ? WHERE id = ?', (code, user_id))
            conn.commit()

        enabled = get_setting(cursor, 'referral_enabled', '1') == '1'
        try:
            percent = float(get_setting(cursor, 'referral_percent', '5') or 5)
        except Exception:
            percent = 5.0

        cursor.execute('''
            SELECT u.id, u.username, u.created_at AS joined,
                   COUNT(o.id) AS purchases,
                   COALESCE((SELECT SUM(r.reward) FROM referral_rewards r WHERE r.referrer_id = ? AND r.referred_user_id = u.id), 0.0) AS commission
            FROM users u
            LEFT JOIN orders o ON o.user_id = u.id
            WHERE u.referred_by = ?
            GROUP BY u.id, u.username, u.created_at
            ORDER BY u.id DESC
        ''', (user_id, user_id))
        referred = [
            {
                'username': row['username'],
                'joined': str(row['joined'] or ''),
                'purchases': int(row['purchases'] or 0),
                'commission': round(float(row['commission'] or 0.0), 2),
            }
            for row in cursor.fetchall()
        ]

        cursor.execute('''
            SELECT rr.order_id, COALESCE(u.username, 'User') AS referred_username,
                   rr.order_amount, rr.percent, rr.reward, rr.created_at
            FROM referral_rewards rr
            LEFT JOIN users u ON rr.referred_user_id = u.id
            WHERE rr.referrer_id = ?
            ORDER BY rr.id DESC
            LIMIT 50
        ''', (user_id,))
        rewards = [
            {
                'order_id': row['order_id'],
                'referred_username': row['referred_username'],
                'order_amount': float(row['order_amount'] or 0),
                'percent': float(row['percent'] or 0),
                'reward': float(row['reward'] or 0),
                'created_at': str(row['created_at'] or ''),
            }
            for row in cursor.fetchall()
        ]

        base_url = request.host_url.rstrip('/') if request.host_url else APP_URL
        return jsonify({
            'code': code,
            'link': f"{base_url}/login?ref={code}",
            'enabled': enabled,
            'percent': percent,
            'total_earned': round(float(user['referral_earnings'] or 0.0), 2),
            'referred_count': len(referred),
            'referred': referred,
            'rewards': rewards,
        })
    finally:
        conn.close()
