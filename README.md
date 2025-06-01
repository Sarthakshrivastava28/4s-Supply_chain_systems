# Smart Supply Support System (RBAC)

A modern, role-based access control (RBAC) web application for managing sales, warehouse, production, and support operations. Built with Flask, SQLAlchemy, and Bootstrap, this system provides a seamless workflow for different user roles in a supply chain environment.

## Overview

This project is a full-featured supply support system with:
- Role-based dashboards for Admin, Sales, Warehouse, Production, and Support
- Request management and tracking
- Customer and inventory management
- Support ticketing and SLA monitoring
- Analytics and reporting
- Modern, responsive UI with dark and light themes

## Features

- **User Authentication & RBAC**: Secure login, registration, and role-based access to modules
- **Sales Module**: Raise requests, view records, manage customers, analytics, and support integration
- **Warehouse Module**: Inventory management, dispatch/production decisions, stock reminders, weather risk
- **Production Module**: Track production requests, update stock, analytics
- **Support Module**: Handle support tickets, monitor SLAs, manage queries
- **Admin Dashboard**: View all tables, manage users, and access all modules
- **Modern UI**: Clean, responsive, and visually appealing interfaces for all modules
- **Error Handling**: Custom 403 page with login/register options

## Installation

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd RBAC
   ```
2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Set up the database**
   ```bash
   flask db upgrade
   # or
   python app.py  # The app will auto-create the database on first run
   ```
5. **Run the application**
   ```bash
   flask run
   # or
   python app.py
   ```

## Usage

- Access the app at `http://localhost:5000`
- Register a new user and select a role (admin, sales, warehouse, production, support)
- Use the dashboard to navigate between modules
- Admins can view all tables and manage the system
- Each module provides role-specific features and analytics

## Project Structure

- `app.py` — Main Flask application and routes
- `models.py` — Database models
- `templates/` — HTML templates for all modules and pages
- `static/` — Static files (CSS, JS, images)
- `requirements.txt` — Python dependencies

## License

This project is licensed under the MIT License. 