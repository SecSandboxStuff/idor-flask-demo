"""Order-tracking web API (Flask + SQLAlchemy + Flask-Login).

Authentication is enforced everywhere via @login_required, so every request is
tied to a logged-in user. Authorization, however, is not: the single-order
endpoint fetches an order purely by its client-supplied primary key and never
checks that the order belongs to the caller.

That is CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR).
"""

from decimal import Decimal

from flask import Flask, abort, jsonify, request
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
)
from werkzeug.security import check_password_hash, generate_password_hash


from models import Order, User, db

app = Flask(__name__)
app.config["SECRET_KEY"] = "demo-not-a-real-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///orders.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    user = User.query.filter_by(username=body.get("username")).first()
    if user is None or not check_password_hash(user.password_hash, body.get("password", "")):
        abort(401)
    login_user(user)
    return jsonify(status="ok", user_id=user.id)


# ---------------------------------------------------------------------------
# VULNERABLE endpoint (CWE-639)
# ---------------------------------------------------------------------------
@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    """Fetch a single order by its id.

    order_id is a user-controlled key taken straight from the URL path. The
    lookup is keyed only by that id — there is no comparison of order.user_id
    to current_user.id, and no owner clause in the query. Any authenticated
    user can therefore read any other user's order by guessing/enumerating ids.
    """
    order = db.session.get(Order, order_id)
    if order is None:
        abort(404)
    return jsonify(
        id=order.id,
        item=order.item,
        amount=str(order.amount),
        user_id=order.user_id,
    )


# ---------------------------------------------------------------------------
# CORRECT counterpart, shown for contrast: this listing is scoped to the
# caller's own orders via an owner clause, so it is NOT an IDOR.
# ---------------------------------------------------------------------------
@app.route("/api/orders")
@login_required
def list_my_orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"id": o.id, "item": o.item, "amount": str(o.amount)} for o in orders])


def _seed():
    """Create the schema and a little demo data for two distinct users."""
    db.create_all()
    if User.query.first() is not None:
        return
    alice = User(username="alice", password_hash=generate_password_hash("alicepw"))
    bob = User(username="bob", password_hash=generate_password_hash("bobpw"))
    db.session.add_all([alice, bob])
    db.session.commit()
    db.session.add_all(
        [
            Order(user_id=alice.id, item="Laptop", amount=Decimal("1299.00")),
            Order(user_id=bob.id, item="Headphones", amount=Decimal("199.00")),
        ]
    )
    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        _seed()
    app.run(debug=True)
