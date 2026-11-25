import os
from flask import Flask, redirect, session, url_for

from core.config import APP_URL, SECRET_KEY
from core.security import register_security_middleware
from database import init_db
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.pages import pages_bp
from routes.store import store_bp
from routes.wallet import wallet_bp


def create_app() -> Flask:
    flask_app = Flask(__name__)
    flask_app.secret_key = SECRET_KEY

    flask_app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=APP_URL.startswith('https://') and os.getenv('FLASK_ENV') == 'production',
        PERMANENT_SESSION_LIFETIME=86400 * 7,
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    )

    init_db()
    register_security_middleware(flask_app)

    flask_app.register_blueprint(pages_bp)
    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(store_bp)
    flask_app.register_blueprint(wallet_bp)
    flask_app.register_blueprint(admin_bp)

    @flask_app.errorhandler(404)
    def handle_404(_err):
        if 'user_id' not in session:
            return redirect(url_for('pages.login_page'))
        return redirect(url_for('pages.dashboard_page'))

    return flask_app


app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f">> Kova Store running at http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', '0') == '1')
