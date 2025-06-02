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



