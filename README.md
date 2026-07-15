# idor-flask-demo

A tiny Flask + SQLAlchemy order-tracking API that intentionally contains a
**CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)**.

## The vulnerability

`GET /api/orders/<int:order_id>` (`app.py`, `get_order`) is protected by
`@login_required`, so the caller must be authenticated. But the handler looks
the order up **only** by the `order_id` from the URL:

```python
order = db.session.get(Order, order_id)
```

It never compares `order.user_id` to `current_user.id` and the query has no
owner clause. Any logged-in user can read any other user's order by changing
the id in the path — the classic Tier-2 IDOR (authenticated but not
authorized).

### Proof of concept

```bash
# log in as bob, then read alice's order (id 1) that belongs to someone else
curl -c jar -X POST localhost:5000/login -d '{"username":"bob","password":"bobpw"}' -H 'Content-Type: application/json'
curl -b jar localhost:5000/api/orders/1   # returns alice's "Laptop" order
```

## The correct pattern, for contrast

`GET /api/orders` (`list_my_orders`) scopes results to the caller with
`Order.query.filter_by(user_id=current_user.id)` — an owner clause — so it is
**not** an IDOR.

## Run

```bash
pip install -r requirements.txt
python app.py
```
