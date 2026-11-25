import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY', 'default-ovk-shop-dev-secret-12345')
PAYMONGO_SECRET_KEY = os.getenv('PAYMONGO_SECRET_KEY', '').strip()
PAYMONGO_PUBLIC_KEY = os.getenv('PAYMONGO_PUBLIC_KEY', '').strip()
PAYMONGO_WEBHOOK_SECRET = os.getenv('PAYMONGO_WEBHOOK_SECRET', '').strip()
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '').strip()
ALLOW_SANDBOX_DEPOSIT = os.getenv('ALLOW_SANDBOX_DEPOSIT', '0').strip() == '1'

raw_app_url = os.getenv('APP_URL', 'http://localhost:5000').strip().rstrip('/')
if raw_app_url and not raw_app_url.startswith(('http://', 'https://')):
    raw_app_url = f"https://{raw_app_url}"
if raw_app_url.endswith('/dashboard'):
    raw_app_url = raw_app_url[:-10]
APP_URL = raw_app_url.rstrip('/')

ALLOWED_DEPOSIT_AMOUNTS = [70.0, 100.0, 150.0, 200.0, 250.0, 300.0, 320.0, 500.0, 700.0, 1000.0]
ALLOWED_IMAGE_EXTS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def get_admin_passkey() -> str:
    return os.getenv('ADMIN_PASSKEY', 'Rovic1925').strip()


def is_live_paymongo() -> bool:
    return bool(PAYMONGO_SECRET_KEY and PAYMONGO_SECRET_KEY.startswith('sk_live_'))


def get_setting(cursor, key: str, default=None):
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    if not row:
        return default
    return row['value'] if isinstance(row, dict) or hasattr(row, 'keys') else row[0]


def set_setting(cursor, key: str, value):
    cursor.execute('UPDATE settings SET value = ? WHERE key = ?', (str(value), key))
    if cursor.rowcount == 0:
        cursor.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
