from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from functools import wraps

role_bp = Blueprint('roles', __name__)

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@role_bp.route('/admin')
@login_required
@role_required('admin')
def admin_page():
    return render_template('admin.html')

@role_bp.route('/sales')
@login_required
@role_required('admin', 'sales')
def sales_page():
    return render_template('sales.html')

@role_bp.route('/warehouse')
@login_required
@role_required('admin', 'warehouse')
def warehouse_page():
    return render_template('warehouse.html')

@role_bp.route('/production')
@login_required
@role_required('admin', 'production')
def production_page():
    return render_template('production.html')

@role_bp.route('/support')
@login_required
@role_required('admin', 'support')
def support_page():
    return render_template('support.html')