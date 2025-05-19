from extensions import db, login_manager
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)  # Required
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    membership_type = db.Column(db.String(50), nullable=False)
    member_since = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    shares = db.Column(db.Integer, default=0)
    monthly_deposit = db.Column(db.Float, default=0.0)
    savings_balance = db.Column(db.Float, default=0.0)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_type = db.Column(db.String(100), nullable=False)  # Personal, Business, etc.
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    doc_type = db.Column(db.String(50))  # ID, Proof of Address, etc.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Transaction(db.Model):
    __tablename__ = 'transaction'  # Explicit table name

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    account_type = db.Column(db.String(50), nullable=True)  # Temporarily nullable
    transaction_type = db.Column(db.String(50), nullable=True)  # Temporarily nullable


class ShareTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    shares = db.Column(db.Integer, nullable=False)  # positive for buy, negative for sell
    total_shares = db.Column(db.Integer, nullable=False)
    price_per_share = db.Column(db.Float, nullable=False, default=10.0)