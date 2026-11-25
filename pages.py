from flask import Blueprint, redirect, render_template, session, url_for
from core.security import admin_required, ensure_csrf_token, login_required

pages_bp = Blueprint('pages', __name__)


@pages_bp.route('/')
def home_page():
    if 'user_id' in session:
        return redirect(url_for('pages.dashboard_page'))
    return redirect(url_for('pages.login_page'))


@pages_bp.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('pages.dashboard_page'))
    ensure_csrf_token()
    return render_template('login.html')


@pages_bp.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html')


@pages_bp.route('/products')
@login_required
def products_page():
    return render_template('products.html')


@pages_bp.route('/product/<int:item_id>')
@login_required
def product_detail_page(item_id):
    return render_template('product_detail.html', item_id=item_id)


@pages_bp.route('/tutorial')
@login_required
def tutorial_page():
    return render_template('tutorial.html')


@pages_bp.route('/referrals')
@login_required
def referrals_page():
    return render_template('referrals.html')


@pages_bp.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html')
