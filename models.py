from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    
    customer_code = db.Column(db.String(20), unique=True, nullable=False)  # 🔹 NEW FIELD
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    requests = db.relationship('Request', backref='customer', lazy=True)



# 👤 User model with roles: sales, warehouse, production, support, admin
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    requests = db.relationship('Request', backref='submitter', lazy=True)


# 📝 Request model created by Sales Executive
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    customer_code = db.Column(db.String(50), nullable=False)  # <-- Newly added
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    priority = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='New')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.Text, nullable=True)


# 📦 Inventory table managed by Warehouse & updated by Production
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    item_name = db.Column(db.String(100), unique=True, nullable=False)  # e.g., "Mouse", "Monitor"
    stock_quantity = db.Column(db.Integer, nullable=False, default=0)   # Available quantity

    low_stock_threshold = db.Column(db.Integer, default=5)  # 🔔 For low stock alerts
    
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  


# 🏪 Warehouse Action
class WarehouseAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    request = db.relationship('Request', backref='warehouse_action', uselist=False)

    decision = db.Column(db.String(100))  # Dispatched / Sent to Production
    stock_status = db.Column(db.String(50))  # In Stock / Low
    risk_tag = db.Column(db.String(100))  # e.g., "Rain Delay"
    handled_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    action_time = db.Column(db.DateTime, default=datetime.utcnow)


# 🏭 Production Task
class ProductionTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    request = db.relationship('Request', backref='production_task', uselist=False)

    item_name = db.Column(db.String(100), nullable=False)  # For redundancy/logging
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='In Progress')  # In Progress / Done
    eta = db.Column(db.DateTime)
    temp_risk = db.Column(db.String(100))  # Mock temp API impact
    completed_at = db.Column(db.DateTime)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))


# 🛠️ Support Ticket
class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    request = db.relationship('Request', backref='support_tickets')

    status = db.Column(db.String(50), default='Open')
    sentiment = db.Column(db.String(100))
    auto_reply = db.Column(db.String(200))  # This is system-generated; not user input
    priority = db.Column(db.String(50))
    department = db.Column(db.String(100))

    sla_title = db.Column(db.String(100))
    sla_description = db.Column(db.String(300))

    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 🧾 Audit Log
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200))  # e.g., "Created Request"
    module = db.Column(db.String(100))  # Sales, Warehouse, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
