# ------------------ Imports ------------------
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Request,SupportTicket,Customer
from datetime import datetime, timezone
import requests
import pandas as pd
from io import BytesIO
from flask_migrate import Migrate
import random
import string
















# ------------------ App Configuration ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = "sarthak"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///db.sqlite3'
EXCHANGE_API_KEY = "075e16bd4130b6d17b01d4ad"

db.init_app(app)
migrate = Migrate(app, db)

# ------------------ Login Manager Setup ------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ------------------ Custom Role Decorator ------------------
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ------------------ Load User for Flask-Login ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ Static Pages ------------------
@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/get-started')
def get_started():
    return render_template('get_started.html')

# ------------------ Registration Route ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()

        flash('Registered successfully. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

# ------------------ Login Route ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            # Redirect based on user role
            role = user.role.lower()
            if role == 'admin':
                return redirect(url_for('admin_page'))
            elif role == 'sales':
                return redirect(url_for('sales_page'))
            elif role == 'warehouse':
                return redirect(url_for('warehouse_page'))
            elif role == 'production':
                return redirect(url_for('production_page'))
            elif role == 'support':
                return redirect(url_for('support_page'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")

    return render_template('login.html')

# ------------------ Logout Route ------------------
@app.route('/logout', methods=["GET", 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------ Dashboard ------------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# ------------------ Role-Based Routes ------------------
@app.route('/admin')
@login_required
@role_required('admin')
def admin_page():
    return render_template('admin.html')

@app.route('/sales')
@login_required
@role_required('admin', 'sales')
def sales_page():
    return render_template('sales.html')

@app.route('/warehouse')
@login_required
@role_required('admin', 'warehouse')
def warehouse_page():
    return render_template('warehouse.html')

@app.route('/production')
@login_required
@role_required('admin', 'production')
def production_page():
    return render_template('production.html')

@app.route('/support')
@login_required
@role_required('admin', 'support')
def support_page():
    return render_template('support.html')

# ------------------ Raise Request Form ------------------
@app.route('/raise-request', methods=['GET', 'POST'])
@login_required
def raise_request():
    if request.method == 'POST':
        customer_name = request.form.get('customer_name')
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        priority = request.form.get('priority')
        description = request.form.get('description')

        if not customer_name or not item_name or not quantity or not priority:
            flash('Please fill all required fields.', 'error')
            return redirect(url_for('raise_request'))

        try:
            new_request = Request(
                customer_name=customer_name,
                item_name=item_name,
                quantity=int(quantity),
                priority=priority,
                description=description,
                status='New',
                created_at=datetime.now(timezone.utc),
                submitted_by=current_user.id
            )
            db.session.add(new_request)
            db.session.commit()
            flash('Request submitted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print("Error while submitting request:", e)
            flash(f'Error submitting request: {str(e)}', 'error')

        return redirect(url_for('raise_request'))

    return render_template('raise_request.html')

# ------------------ View All Requests ------------------
@app.route('/request-records')
def records_sales():
    all_requests = Request.query.all()
    return render_template('records_sales.html', requests=all_requests)

# ------------------ Currency Exchange API ------------------
@app.route('/currency-rate')
def get_exchange_rate():
    base = request.args.get('base', 'USD')
    target = request.args.get('target', 'INR')

    url = f'https://v6.exchangerate-api.com/v6/{EXCHANGE_API_KEY}/pair/{base}/{target}'
    response = requests.get(url)
    data = response.json()

    if data['result'] == 'success':
        return jsonify({
            'rate': data['conversion_rate'],
            'base': base,
            'target': target
        })
    else:
        return jsonify({'error': 'Unable to fetch rate'}), 400

# ------------------ Currency Checker Page ------------------
@app.route('/currency-dashboard')
def currency_page():
    return render_template('currency_checker.html')

# ------------------ Export Requests as Excel ------------------
@app.route('/export-requests')
def export_requests():
    requests_data = Request.query.all()
    data = [{
        'ID': r.id,
        'Customer': r.customer_name,
        'Item': r.item_name,
        'Quantity': r.quantity,
        'Priority': r.priority,
        'Status': r.status,
        'Submitted By': r.submitted_by,
        'Created At': r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        'Description': r.description
    } for r in requests_data]

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Requests')
    output.seek(0)

    return send_file(output, download_name='requests_export.xlsx', as_attachment=True)

# ------------------ Sales Analytics Page ------------------
@app.route('/sales-analytics')
def analytics_sales():
    requests = Request.query.all()
    total = len(requests)
    new_count = sum(1 for r in requests if r.status == "New")
    production_count = sum(1 for r in requests if r.status == "Needs Production")
    dispatched_count = sum(1 for r in requests if r.status == "Dispatched")

    status_data = {
        "New": new_count,
        "Needs Production": production_count,
        "Dispatched": dispatched_count
    }

    priority_data = {}
    for r in requests:
        priority_data[r.priority] = priority_data.get(r.priority, 0) + 1

    return render_template("analytics_sales.html",
        total=total,
        new_count=new_count,
        production_count=production_count,
        dispatched_count=dispatched_count,
        status_data=status_data,
        priority_data=priority_data
    ) 

# ------------------ Mock Inventory API ------------------
@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    mock_inventory = {
        "Mouse": {"stock": 85, "location": "Warehouse B"},
        "Printer": {"stock": 15, "location": "Warehouse C"},
        "Scanner": {"stock": 10, "location": "Warehouse A"},
        "Webcam": {"stock": 50, "location": "Warehouse B"},
        "Headset": {"stock": 70, "location": "Warehouse C"},
        "Cables": {"stock": 300, "location": "Warehouse A"},
        "Software License": {"stock": 200, "location": "Cloud Server"},
        "Laptop": {"stock": 40, "location": "Warehouse D"},
        "Tablet": {"stock": 30, "location": "Warehouse E"},
        "Docking Station": {"stock": 25, "location": "Warehouse D"},
        "Projector": {"stock": 12, "location": "Warehouse B"},
        "UPS": {"stock": 18, "location": "Warehouse F"}
    }
    return jsonify(mock_inventory)

# ------------------ Inventory Display Page ------------------
@app.route('/manage-customers-sales', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        customer_code = request.form.get('customer_code', '').strip()

        if not name or not customer_code:
            flash("Name and Customer Code are required.", "danger")
            return redirect(url_for('add_customer'))

        if email:
            existing_email = Customer.query.filter_by(email=email).first()
            if existing_email:
                flash("Customer with this email already exists!", "danger")
                return redirect(url_for('add_customer'))

        existing_code = Customer.query.filter_by(customer_code=customer_code).first()
        if existing_code:
            flash("Customer code already exists. Please refresh the form and try again.", "danger")
            return redirect(url_for('add_customer'))

        new_customer = Customer(
            name=name,
            email=email or None,
            phone=phone or None,
            customer_code=customer_code,
            user_id=current_user.id
        )
        db.session.add(new_customer)
        db.session.commit()

        flash("Customer added successfully!", "success")
        return redirect(url_for('add_customer'))

    # GET: Show customers added by current user
    all_customers = Customer.query.filter_by(user_id=current_user.id).order_by(Customer.id.desc()).all()
    return render_template('add_customer.html', customers=all_customers)




































































































@app.route('/api/customer-request-support', methods=['GET'])
@login_required
@role_required('admin', 'sales', 'support')
def customer_requests_api():
    requests_data = Request.query.all()
    output = [
        {
            'id': r.id,
            'customer_name': r.customer_name,
            'item_name': r.item_name,
            'priority': r.priority
        } for r in requests_data
    ]
    return jsonify(output)


@app.route('/customer-manager-support')
@login_required
@role_required('admin', 'sales', 'support')
def customer_manager_support():
    return render_template('customer_manager_support.html')




@app.route('/raise-support-request', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'support', 'sales')
def raise_support_request():
    if request.method == 'GET':
        return render_template('raise_request_support.html')

    # POST logic
    try:
        data = request.get_json()
        print("Received data:", data)  # Debugging

        request_id = data.get('request_id')
        priority = data.get('priority')
        department = data.get('department')
        status = data.get('status', 'Open')
        sentiment = data.get('sentiment')
        auto_reply = data.get('auto_reply')

        if not request_id or not priority:
            return jsonify({'error': 'Request ID and Priority are required'}), 400

        new_ticket = SupportTicket(
            request_id=request_id,
            priority=priority,
            department=department,
            status=status,
            sentiment=sentiment,
            auto_reply=auto_reply,
            created_by=current_user.id
        )

        db.session.add(new_ticket)
        db.session.commit()

        return jsonify({'message': 'Support ticket submitted successfully'}), 201

    except Exception as e:
        db.session.rollback()
        print("Error:", e)
        return jsonify({'error': 'Failed to submit support request'}), 500









# ------------------ Custom 403 Error Page ------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# ------------------ App Runner ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
