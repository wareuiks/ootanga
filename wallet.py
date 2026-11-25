import base64
import hashlib
import hmac
import json
import uuid
import requests
from flask import Blueprint, jsonify, request, session

from core.config import (
    ALLOW_SANDBOX_DEPOSIT,
    ALLOWED_DEPOSIT_AMOUNTS,
    APP_URL,
    PAYMONGO_SECRET_KEY,
    PAYMONGO_WEBHOOK_SECRET,
    is_live_paymongo,
)
from core.security import log_security, login_required
from database import get_db

wallet_bp = Blueprint('wallet', __name__)


def _fetch_paymongo_session(session_id: str) -> dict | None:
    if not PAYMONGO_SECRET_KEY or 'demo_key' in PAYMONGO_SECRET_KEY:
        return None
    auth_header = base64.b64encode(f"{PAYMONGO_SECRET_KEY}:".encode('utf-8')).decode('utf-8')
    res = requests.get(
        f'https://api.paymongo.com/v1/checkout_sessions/{session_id}',
        headers={'Authorization': f'Basic {auth_header}'},
        timeout=12,
    )
    if res.status_code != 200:
        return None
    return res.json().get('data', {})


def _credit_deposit_once(cursor, session_id: str, user_id: int, amount: float, description: str) -> bool:
    """Idempotently transition deposit transaction to completed and credit user balance atomically."""
    cursor.execute('SELECT id, status FROM transactions WHERE reference_id = ?', (session_id,))
    tx = cursor.fetchone()
    if tx:
        if tx['status'] == 'completed':
            return False
        cursor.execute(
            "UPDATE transactions SET status = 'completed', description = ? WHERE reference_id = ? AND status != 'completed'",
            (description, session_id),
        )
        if cursor.rowcount == 0:
            return False
    else:
        cursor.execute('''
            INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
            VALUES (?, ?, 'deposit', ?, 'completed', ?)
        ''', (session_id, user_id, amount, description))

    cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
    return True


@wallet_bp.route('/api/wallet/create-checkout', methods=['POST'])
@login_required
def create_paymongo_checkout():
    data = request.get_json() or {}
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Enter a valid numeric amount.'}), 400

    if amount not in ALLOWED_DEPOSIT_AMOUNTS:
        return jsonify({'error': 'Select a valid preset deposit amount.'}), 400

    user_id = session['user_id']
    username = session.get('username', f'User #{user_id}')
    amount_in_centavos = int(round(amount * 100))

    is_demo_key = not PAYMONGO_SECRET_KEY or 'demo_key' in PAYMONGO_SECRET_KEY or 'paste_your' in PAYMONGO_SECRET_KEY
    if is_demo_key:
        return jsonify({
            'demo_mode': True,
            'message': 'PayMongo is in sandbox mode.',
            'amount': amount
        })

    auth_header = base64.b64encode(f"{PAYMONGO_SECRET_KEY}:".encode('utf-8')).decode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {auth_header}'
    }

    payload = {
        'data': {
            'attributes': {
                'send_email_receipt': True,
                'show_description': True,
                'show_line_items': True,
                'description': f"Wallet Deposit for {username} (ID: {user_id})",
                'line_items': [
                    {
                        'currency': 'PHP',
                        'amount': amount_in_centavos,
                        'name': f"Wallet Deposit (PHP {amount:.2f})",
                        'quantity': 1,
                        'description': f"Balance top-up for {username}"
                    }
                ],
                'payment_method_types': ['gcash', 'paymaya', 'card', 'qrph', 'grab_pay'],
                'success_url': f"{APP_URL}/dashboard?deposit=success&session_id={{CHECKOUT_SESSION_ID}}",
                'cancel_url': f"{APP_URL}/dashboard?deposit=cancelled",
                'metadata': {
                    'userId': str(user_id),
                    'type': 'wallet_deposit',
                    'amountPhp': f"{amount:.2f}",
                    'username': username
                }
            }
        }
    }

    try:
        response = requests.post(
            'https://api.paymongo.com/v1/checkout_sessions',
            headers=headers,
            json=payload,
            timeout=15
        )
        resp_data = response.json()

        if response.status_code not in (200, 201):
            err_msg = 'PayMongo Error: '
            if 'errors' in resp_data and len(resp_data['errors']) > 0:
                err_msg += resp_data['errors'][0].get('detail', 'Unknown error')
            else:
                err_msg += 'Could not create checkout session.'
            return jsonify({'error': err_msg}), 400

        checkout_data = resp_data.get('data', {})
        checkout_url = checkout_data.get('attributes', {}).get('checkout_url')
        session_id = checkout_data.get('id')

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT id FROM transactions WHERE reference_id = ?', (session_id,))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
                    VALUES (?, ?, 'deposit', ?, 'pending', ?)
                ''', (session_id, user_id, amount, f"PayMongo Checkout Session ({amount:.2f} PHP)"))
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            'success': True,
            'checkout_url': checkout_url,
            'session_id': session_id
        })
    except Exception:
        return jsonify({'error': 'Failed to reach payment gateway.'}), 502


@wallet_bp.route('/api/wallet/verify-checkout', methods=['POST'])
@login_required
def verify_paymongo_checkout():
    data = request.get_json() or {}
    session_id = (data.get('session_id') or '').strip()
    user_id = int(session['user_id'])

    if not session_id or not session_id.startswith('cs_'):
        return jsonify({'error': 'Valid session_id required.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, status, amount FROM transactions WHERE reference_id = ? AND user_id = ?', (session_id, user_id))
        tx = cursor.fetchone()
        if not tx:
            return jsonify({'error': 'Checkout session not found for this account.'}), 404
        if tx['status'] == 'completed':
            return jsonify({'success': True, 'status': 'completed', 'already_credited': True})

        pm_data = _fetch_paymongo_session(session_id)
        if not pm_data:
            return jsonify({'error': 'Unable to verify checkout with PayMongo.'}), 400

        attributes = pm_data.get('attributes', {})
        payments = attributes.get('payments', [])
        status = attributes.get('status')
        is_paid = (len(payments) > 0 and payments[0].get('attributes', {}).get('status') == 'paid') or status == 'paid'

        if not is_paid:
            return jsonify({'success': False, 'status': 'pending', 'message': 'Payment is still processing.'})

        amount = float(tx['amount'])
        credited = _credit_deposit_once(cursor, session_id, user_id, amount, f"PayMongo Instant Paid (₱{amount:.2f})")
        conn.commit()

        return jsonify({
            'success': True,
            'status': 'completed',
            'already_credited': not credited,
            'credited': amount,
            'message': f"Credited ₱{amount:.2f} to your wallet!"
        })
    except Exception:
        conn.rollback()
        return jsonify({'error': 'Verification failed.'}), 500
    finally:
        conn.close()


@wallet_bp.route('/api/wallet/simulate-deposit', methods=['POST'])
@login_required
def simulate_deposit():
    if is_live_paymongo() and not ALLOW_SANDBOX_DEPOSIT:
        log_security('sandbox_deposit_blocked', 'attempted simulate-deposit while live key active')
        return jsonify({'error': 'Sandbox deposits are disabled in live payment mode.'}), 403

    if session.get('role') != 'admin' and not ALLOW_SANDBOX_DEPOSIT:
        log_security('sandbox_deposit_blocked', 'non-admin attempted simulate-deposit')
        return jsonify({'error': 'Sandbox deposits require administrator privileges.'}), 403

    data = request.get_json() or {}
    try:
        amount = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid amount.'}), 400

    if amount not in ALLOWED_DEPOSIT_AMOUNTS:
        return jsonify({'error': 'Select a valid preset deposit amount.'}), 400

    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    try:
        ref_id = f"DEP-SIM-{uuid.uuid4().hex[:8].upper()}"
        cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        cursor.execute('''
            INSERT INTO transactions (reference_id, user_id, type, amount, status, description)
            VALUES (?, ?, 'deposit', ?, 'completed', ?)
        ''', (ref_id, user_id, amount, f"Sandbox Top-Up (₱{amount:.2f})"))
        conn.commit()

        cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        updated_balance = cursor.fetchone()['balance']
        return jsonify({
            'success': True,
            'message': f'Added ₱{amount:.2f} to your wallet!',
            'new_balance': float(updated_balance)
        })
    finally:
        conn.close()


@wallet_bp.route('/api/webhooks/paymongo', methods=['POST'])
def paymongo_webhook():
    raw_body = request.get_data()
    signature_header = request.headers.get('Paymongo-Signature', '')

    try:
        event = json.loads(raw_body.decode('utf-8'))
    except Exception:
        return jsonify({'error': 'Invalid JSON body'}), 400

    has_real_secret = bool(PAYMONGO_WEBHOOK_SECRET and 'demo' not in PAYMONGO_WEBHOOK_SECRET)
    signature_verified = False

    if has_real_secret:
        if not signature_header:
            log_security('webhook_reject', 'missing Paymongo-Signature')
            return jsonify({'error': 'Missing signature'}), 401
        parts = dict(item.split('=', 1) for item in signature_header.split(',') if '=' in item)
        timestamp = parts.get('t', '')
        received_sig = parts.get('li') or parts.get('te') or ''
        if not timestamp or not received_sig:
            log_security('webhook_reject', 'malformed Paymongo-Signature')
            return jsonify({'error': 'Malformed signature'}), 401

        signed_payload = f"{timestamp}.{raw_body.decode('utf-8')}"
        expected_sig = hmac.new(
            PAYMONGO_WEBHOOK_SECRET.encode('utf-8'),
            signed_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, received_sig):
            log_security('webhook_reject', 'invalid Paymongo-Signature')
            return jsonify({'error': 'Invalid signature'}), 401
        signature_verified = True

    event_type = event.get('data', {}).get('attributes', {}).get('type')
    event_data = event.get('data', {}).get('attributes', {}).get('data', {})

    if event_type in ('checkout_session.payment.paid', 'payment.paid'):
        session_id = (event_data.get('id') or '').strip()
        if not session_id:
            return jsonify({'error': 'Missing session id'}), 400

        # If webhook secret is not configured, verify directly against PayMongo API so webhooks cannot be forged!
        if not signature_verified:
            pm_live = _fetch_paymongo_session(session_id)
            if not pm_live:
                log_security('webhook_reject', f'unverified session {session_id}')
                return jsonify({'error': 'Could not verify webhook session against PayMongo'}), 401
            attributes = pm_live.get('attributes', {})
            payments = attributes.get('payments', [])
            is_paid = (len(payments) > 0 and payments[0].get('attributes', {}).get('status') == 'paid') or attributes.get('status') == 'paid'
            if not is_paid:
                return jsonify({'error': 'Session is not paid'}), 400
        else:
            attributes = event_data.get('attributes', {})

        metadata = attributes.get('metadata', {})
        user_id = metadata.get('userId')
        amount_php_str = metadata.get('amountPhp')

        if not user_id and attributes.get('payments'):
            payment_meta = attributes['payments'][0].get('attributes', {}).get('metadata', {})
            user_id = payment_meta.get('userId')
            amount_php_str = payment_meta.get('amountPhp')

        if user_id:
            conn = get_db()
            cursor = conn.cursor()
            try:
                uid = int(user_id)
                cursor.execute('SELECT amount FROM transactions WHERE reference_id = ? AND user_id = ?', (session_id, uid))
                local_tx = cursor.fetchone()
                if local_tx:
                    amount = float(local_tx['amount'])
                else:
                    amount = float(amount_php_str) if amount_php_str else (attributes.get('amount', 0) / 100.0)

                _credit_deposit_once(cursor, session_id, uid, amount, f"PayMongo Paid via GCash/Card (₱{amount:.2f})")
                conn.commit()
            except Exception:
                conn.rollback()
                return jsonify({'error': 'Webhook processing error'}), 500
            finally:
                conn.close()

    return jsonify({'received': True}), 200
