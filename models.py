"""Database models for the order-tracking demo.

An Order is owned by exactly one User via `Order.user_id`. Access to an order
is therefore *supposed* to be restricted to its owner — but the single-order
endpoint in app.py never enforces that, which is the IDOR (CWE-639).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    orders = db.relationship("Order", backref="owner", lazy=True)


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    # The owning user. This column is what *should* gate access to the order,
    # but get_order() in app.py never compares it to the logged-in principal.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    item = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
