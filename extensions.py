"""
Flask-SQLAlchemy extension. Import db here to avoid circular imports with app.
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
