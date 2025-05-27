from flask import Blueprint

# Import individual blueprints
from .auth_routes import auth_bp

from .role_routes import role_bp

# Optional: You could auto-register blueprints here
def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(role_bp)