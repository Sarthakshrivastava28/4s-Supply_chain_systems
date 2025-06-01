# ------------------ Imports ------------------
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Request,SupportTicket,Customer,Inventory,ProductionTask
import requests
import pandas as pd
from io import BytesIO
from flask_migrate import Migrate
import random
import string
from datetime import date
import random
from datetime import datetime, timezone, timedelta
from sqlalchemy import func












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
# @app.route('/logout', methods=["GET", 'POST'])
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

@app.route('/logout', methods=["GET", 'POST'])
@login_required
def logout():
    logout_user()  # Clears Flask-Login specific session keys
    flash('You have been successfully logged out.', 'info') # Optional: provide user feedback
    
    # Create a response object by redirecting first
    response = redirect(url_for('login'))
    
    # Explicitly tell the browser to delete the session cookie
    # app.session_cookie_name gives the configured name of the session cookie (default: 'session')
    session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
    response.set_cookie(session_cookie_name, '', expires=0, path='/', secure=app.config.get('SESSION_COOKIE_SECURE', False), samesite=app.config.get('SESSION_COOKIE_SAMESITE', None), httponly=app.config.get('SESSION_COOKIE_HTTPONLY', True))
    
    return response
 

# ------------------ Dashboard ------------------
@app.route('/all_tables')
@role_required('admin')
@login_required
def dashboard():
    return render_template('all_tables', user=current_user)

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

# Restore support sales module
@app.route('/support-sales')
@login_required
def support_sales():
    user_id = current_user.id
    # Fetch requests created by the current user
    requests = Request.query.filter_by(submitted_by=user_id).order_by(Request.created_at.desc()).all()
    return render_template('support_sales.html', requests=requests)

@app.route('/send-to-support/<int:request_id>', methods=['POST'])
@login_required
def send_to_support(request_id):
    request_item = Request.query.get_or_404(request_id)
    # Ensure the user owns this request or is an admin/support
    if request_item.submitted_by != current_user.id and current_user.role not in ['admin', 'support']:
        flash('You are not authorized to perform this action.', 'danger')
        return redirect(url_for('support_sales'))

    request_item.status = 'Sent to Support'
    db.session.commit()
    flash('Request sent to support successfully.', 'success')
    return redirect(url_for('support_sales'))

# ------------------ Raise Request Form ------------------
@app.route('/raise-request', methods=['GET', 'POST'])
@login_required
def raise_request():
    # Get only customers added by this user
    customers = Customer.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        customer_code = request.form.get('customer_code')
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        priority = request.form.get('priority')
        description = request.form.get('description')
        status = request.form.get('status')  # Optional dynamic status input

        print("Posted values:", customer_code, item_name, quantity, priority, description, status)

        # Validate required fields
        if not customer_code or not item_name or not quantity or not priority:
            flash('Please fill all required fields.', 'error')
            return redirect(url_for('raise_request'))

        try:
            # Check customer ownership and existence
            customer = Customer.query.filter_by(customer_code=customer_code, user_id=current_user.id).first()
            if not customer:
                flash("Invalid or unauthorized customer code.", "error")
                return redirect(url_for('raise_request'))

            # Create new request with correct foreign key
            new_request = Request(
                customer_id=customer.id,
                customer_code=customer.customer_code,  # Still stored for easy filtering
                item_name=item_name,
                quantity=int(quantity),
                priority=priority,
                description=description,
                status=status if status else 'New',
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

    return render_template('raise_request.html', customers=customers)
# ------------------ View All Requests ------------------
@app.route('/request-records')
@login_required
def my_requests():
    user_id = current_user.id
    requests = Request.query.filter_by(submitted_by=user_id).order_by(Request.created_at.desc()).all()
    return render_template('records_sales.html', requests=requests)

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
 
































# ------------------ Warehouse Module ------------------

@app.route('/view-requests-warehouse')

@role_required('admin', 'warehouse')
def view_requests_warehouse():
    requests = Request.query.order_by(Request.created_at.desc()).all()
    return render_template('view_requests_warehouse.html', requests=requests)





@app.route('/warehouse/process_request_action/<int:request_id>', methods=['POST'], endpoint='process_request_action')
@login_required
@role_required('admin', 'warehouse')
def process_request_action(request_id):
    req_to_process = Request.query.get_or_404(request_id)
    action = request.form.get('action')

    if not action:
        flash("No action specified.", "error")
        return redirect(url_for('dispatch_decision'))

    try:
        if action == 'dispatch':
            if req_to_process.status == "Dispatched":
                flash(f"Request {req_to_process.id} is already Dispatched.", "info")
                return redirect(url_for('dispatch_decision'))

            inventory_item = Inventory.query.filter_by(item_name=req_to_process.item_name).first()
            if not inventory_item:
                flash(f"Inventory item '{req_to_process.item_name}' not found.", "error")
            elif inventory_item.stock_quantity < req_to_process.quantity:
                flash(f"Not enough stock for '{req_to_process.item_name}'. Available: {inventory_item.stock_quantity}, Needed: {req_to_process.quantity}. Send to production instead.", "error")
            else:
                inventory_item.stock_quantity -= req_to_process.quantity
                inventory_item.last_updated = datetime.now(timezone.utc)
                req_to_process.status = "Dispatched"
                # Optionally, set a dispatched_at timestamp if your Request model has one
                # req_to_process.dispatched_at = datetime.now(timezone.utc)
                flash(f"Request {req_to_process.id} for '{req_to_process.item_name}' has been Dispatched. Inventory updated.", "success")
        
        elif action == 'send_to_production':
            if req_to_process.status == "Needs Production":
                 flash(f"Request {req_to_process.id} is already marked as 'Needs Production'.", "info")
            else:
                req_to_process.status = "Needs Production"
                flash(f"Request {req_to_process.id} for '{req_to_process.item_name}' has been sent to Production.", "success")
        else:
            flash("Invalid action specified.", "error")

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f"Error processing request: {str(e)}", "error")
        print(f"Error in process_request_action: {e}") # For server-side logging

    return redirect(url_for('dispatch_decision'))


@app.route('/dispatch-decision')
@login_required
@role_required('warehouse', 'admin')
def dispatch_decision():
    # Fetch requests needing attention, including 'Ready for Dispatch' and 'Sent to Production'
    statuses_to_include = ['New', 'Needs Production', 'Ready for Dispatch', 'Sent to Production']
    requests_to_process = Request.query.filter(Request.status.in_(statuses_to_include)).order_by(Request.created_at.asc()).all()
    inventory_items_list = Inventory.query.all()
    inventory_map = {item.item_name: item.stock_quantity for item in inventory_items_list}

    processed_requests = []
    for req in requests_to_process:
        stock_available = inventory_map.get(req.item_name, 0)
        req.is_in_stock = stock_available >= req.quantity
        req.current_stock = stock_available
        processed_requests.append(req)
    
    return render_template('dispatch_production.html',
                           requests=processed_requests,
                           inventory_items=inventory_items_list) 
 


@app.route('/warehouse-dashboard')
@login_required
@role_required('warehouse')
def warehouse_dashboard():
    return render_template("warehouse.html")




@app.route('/check-stock', methods=['POST'])
@login_required
@role_required('warehouse')  # or other roles allowed
def check_stock():
    data = request.get_json()
    product_name = data.get('product_name')
    quantity = data.get('quantity')

    if not product_name or quantity is None:
        return jsonify({'message': 'Product name and quantity are required.'}), 400

    inventory_item = Inventory.query.filter_by(item_name=product_name).first()

    if not inventory_item:
        return jsonify({'message': f'Product "{product_name}" not found in inventory.'}), 404

    if inventory_item.stock_quantity >= quantity:
        return jsonify({'message': f'✅ In stock: {inventory_item.stock_quantity} available.'})
    else:
        return jsonify({
            'message': f'⚠️ Not enough stock. Only {inventory_item.stock_quantity} available.'
        })



@app.route('/warehouse/request-status')
@login_required
@role_required('warehouse')
def warehouse_request_status():
    inventory_items = Inventory.query.all()
    requests = Request.query.filter(Request.status.in_(['New', 'Needs Production'])).all()
    return render_template('warehouse_request_status.html', inventory_items=inventory_items, requests=requests)





# ------------------ Daily Dispatch Summary ------------------



@app.route('/daily-dispatch-summary')
def daily_dispatch_summary():
    # Fetch all requests where status is 'dispatched'
    dispatched_requests = Request.query.filter_by(status='Dispatched').all()

    return render_template('daily_summary_warehouse.html', requests=dispatched_requests)




@app.route("/stock-reminders")
def stock_reminders():
    # Fetch all inventory items from the database
    inventory_items = Inventory.query.all()
    
    # Pass inventory items to the template
    return render_template("stock_level_warehouse.html", items=inventory_items)







from datetime import datetime, timezone, timedelta

@app.route('/sla-monitoring')
@login_required
@role_required('admin', 'warehouse', 'support')
def sla_monitoring():
    # Calculate the timestamp for 48 hours ago
    forty_eight_hours_ago = datetime.now(timezone.utc) - timedelta(hours=48)

    # Query requests that are older than 48 hours and have status New or Needs Production
    overdue_requests = Request.query.filter(
        Request.status.in_(['New', 'Needs Production']),
        Request.created_at <= forty_eight_hours_ago
    ).order_by(Request.created_at.asc()).all()

    # Calculate SLA metrics
    total_overdue = len(overdue_requests)
    new_overdue = sum(1 for r in overdue_requests if r.status == 'New')
    production_overdue = sum(1 for r in overdue_requests if r.status == 'Needs Production')

    # Calculate hours overdue for each request
    for request in overdue_requests:
        created = request.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        hours_overdue = (datetime.now(timezone.utc) - created).total_seconds() / 3600
        request.hours_overdue = round(hours_overdue, 1)

    return render_template('sla_monitoring.html',
                         requests=overdue_requests,
                         total_overdue=total_overdue,
                         new_overdue=new_overdue,
                         production_overdue=production_overdue)



@app.route('/weather-delivery-risk')
# @login_required # Uncomment if this page should require login
def weather_page():
    return render_template('weather_display.html')


@app.route('/api/weather/temperature')
@login_required # Or remove if public access is okay
def mock_temperature_api():
    # Simulate different weather conditions
    conditions = [
        {"condition": "Sunny", "temperature_celsius": round(random.uniform(20, 35), 1)},
        {"condition": "Cloudy", "temperature_celsius": round(random.uniform(15, 25), 1)},
        {"condition": "Rainy", "temperature_celsius": round(random.uniform(10, 20), 1)},
        {"condition": "Stormy", "temperature_celsius": round(random.uniform(10, 18), 1), "wind_mph": round(random.uniform(15, 30),1)},
        {"condition": "Snowy", "temperature_celsius": round(random.uniform(-5, 2), 1)},
        {"condition": "Extreme Heat", "temperature_celsius": round(random.uniform(35, 45), 1), "alert": "Heatwave warning"},
        {"condition": "Freezing", "temperature_celsius": round(random.uniform(-15, -1), 1), "alert": "Frost warning"}
    ]
    
    selected_weather = random.choice(conditions)
    
    response_data = {
        "location": "Mock City",
        "temperature_celsius": selected_weather["temperature_celsius"],
        "condition": selected_weather["condition"],
        "unit": "Celsius",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if "wind_mph" in selected_weather:
        response_data["wind_mph"] = selected_weather["wind_mph"]
    if "alert" in selected_weather:
        response_data["alert"] = selected_weather["alert"]
        
    return jsonify(response_data)





# ------------------ Prodcution Module------------------

@app.route('/production/mark_ready/<int:request_id>', methods=['POST'])
@login_required
@role_required('production', 'admin')
def mark_request_ready_for_dispatch(request_id):
    try:
        prod_request = Request.query.get_or_404(request_id)
        inventory_item = Inventory.query.filter_by(item_name=prod_request.item_name).first()

        if not inventory_item:
            flash(f"Inventory item '{prod_request.item_name}' not found. Cannot mark as ready.", "error")
            return redirect(url_for('production_pending_requests'))

        # Add quantity to inventory
        inventory_item.stock_quantity += prod_request.quantity
        inventory_item.last_updated = datetime.now(timezone.utc)

        # Update request status
        prod_request.status = "Ready for Dispatch"
        # Optionally, set a completed_at or similar timestamp if your Request model has one
        # prod_request.completed_at = datetime.now(timezone.utc)

        db.session.commit()
        flash(f"Request '{prod_request.item_name}' (ID: {prod_request.id}) marked as 'Ready for Dispatch' and inventory updated.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error marking request ready: {str(e)}", "error")
        print(f"Error in mark_request_ready_for_dispatch: {e}") # For server-side logging

    return redirect(url_for('production_pending_requests'))






@app.route('/production-requests')
@login_required
@role_required('admin', 'production')
def production_pending_requests():
    try:
        pending_production = (
            Request.query
            .filter_by(status='Needs Production')
            .order_by(Request.created_at.desc())
            .all()
        )
    except Exception as e:
        flash(f"Error fetching production requests: {str(e)}", "error")
        pending_production = []

    return render_template(
        'production_requests.html',
        production_requests=pending_production,
        title="Pending Production Requests"
    )



@app.route('/live-inventory')
@login_required
# @role_required('production', 'admin') # Add role protection if needed
def live_inventory():
    try:
        # Assuming you have an Inventory model
        inventory_items = Inventory.query.order_by(Inventory.item_name).all()
    except Exception as e:
        flash(f"Error fetching inventory: {str(e)}", "error")
        inventory_items = []
    return render_template('production_live_inventory.html', inventory_items=inventory_items, title="Live Inventory")


@app.route('/production/update_stock', methods=['POST'])
@login_required
# @role_required('production', 'admin') # Add role protection if needed
def update_stock():
    try:
        item_identifier = request.form.get('item_id') # Can be ID or name
        quantity_change = int(request.form.get('quantity'))

        # Find the item by ID or name
        item = Inventory.query.filter((Inventory.id == item_identifier) | (Inventory.item_name == item_identifier)).first()

        if item:
            item.stock_quantity += quantity_change
            item.last_updated = datetime.now(timezone.utc) # Make sure to import timezone
            db.session.commit()
            flash(f"Stock for {item.item_name} updated successfully.", "success")
        else:
            flash(f"Item '{item_identifier}' not found in inventory.", "error")

    except ValueError:
        flash("Invalid quantity. Please enter a number.", "error")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating stock: {str(e)}", "error")
        print(f"Error updating stock: {e}") # For server-side logging

    return redirect(url_for('live_inventory'))


@app.route('/factory-temperature')
@login_required
# @role_required('production', 'admin') # Optional: Add role protection
def production_temperature_page():
    return render_template('production_temperature_check.html', title="Factory Temperature")


@app.route('/api/factory_temperature_status', methods=['GET'])
def factory_temperature_status():
    temperature = random.randint(1, 100)
    status = ""
    if 1 <= temperature <= 33:
        status = "Low - Operations Normal"
    elif 34 <= temperature <= 66:
        status = "Moderate - Monitor Equipment"
    elif 67 <= temperature <= 100:
        status = "High - Alert! Check Cooling Systems"
    else:
        # This case should not be reached if random.randint(1,100) is used
        status = "Unknown - Temperature out of expected range"

    return jsonify({
        'temperature_celsius': temperature,
        'status': status,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })



@app.route('/production-analytics')
@login_required
# @role_required('production', 'admin') # Optional: Add role protection
def production_analytics_page():
    try:
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

        # Query ProductionTask for items completed in the last hour
        # Assuming 'Done' or 'Completed' signifies completion. Adjust if your status is different.
        completed_tasks = db.session.query(
            ProductionTask.item_name,
            func.sum(ProductionTask.quantity).label('total_quantity')
        ).filter(
            ProductionTask.status.in_(['Done', 'Completed']), # Adjust status names if needed
            ProductionTask.completed_at >= one_hour_ago
        ).group_by(ProductionTask.item_name).all()

        if completed_tasks:
            labels = [task.item_name for task in completed_tasks]
            quantities = [task.total_quantity for task in completed_tasks]
            chart_data = {"labels": labels, "quantities": quantities}
        else:
            chart_data = None
            flash("No production tasks completed in the last hour.", "info")

    except Exception as e:
        flash(f"Error fetching production analytics: {str(e)}", "error")
        print(f"Error in production_analytics_page: {e}") # For server-side logging
        chart_data = None

    return render_template('production_analytics.html', title="Production Analytics", chart_data=chart_data)

























# ------------------ Support Module------------------

@app.route('/pending-requests')
@login_required
def pending_requests():
    # TODO: Replace with actual logic to fetch pending requests
    return render_template('support_pending_requests.html')

@app.route('/create-query')
@login_required
def create_query():
    # TODO: Show form to create support query
    return render_template('support_pending_requests.html')

@app.route('/support-sla-monitoring')
@login_required
def support_sla_monitoring():
    # TODO: Display SLA metrics and alerts
    return render_template('support_sla_monitoring.html')








# ------------------ Custom 403 Error Page ------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    But for sensitive pages, ensure they are not cached after logout.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    # response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1' # Usually not needed for modern apps
    # response.headers['Cache-Control'] = 'public, max-age=0' # Default for Flask, might be overridden
    return response


@app.route('/all-tables')
@login_required
@role_required('admin')
def all_tables():
    users = User.query.all()
    customers = Customer.query.all()
    requests = Request.query.all()
    inventory = Inventory.query.all()
    
    
    
    
    return render_template(
        'all_tables.html',
        users=users,
        customers=customers,
        requests=requests,
        inventory=inventory,
        
      
        
    )






# ------------------ App Runner ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

