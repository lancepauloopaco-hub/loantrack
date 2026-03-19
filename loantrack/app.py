from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
import os

app = Flask(__name__)

# ✅ ENV CONFIG (Render-ready)
app.secret_key = os.environ.get("SECRET_KEY", "loan_system_secret_key_2024")

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loan_system.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ─────────────────────────────
# MODELS
# ─────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='staff')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    logs = db.relationship('AdminLog', backref='user', lazy=True)

class Consumer(db.Model):
    __tablename__ = 'consumers'
    consumer_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    contact = db.Column(db.String(20))
    address = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    loans = db.relationship('Loan', backref='consumer', lazy=True, cascade='all, delete-orphan')

class Loan(db.Model):
    __tablename__ = 'loans'
    loan_id = db.Column(db.Integer, primary_key=True)
    consumer_id = db.Column(db.Integer, db.ForeignKey('consumers.consumer_id'), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    loan_term = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.Date, default=date.today)
    due_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='ongoing')
    penalty_rate = db.Column(db.Float, default=2.0)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payments = db.relationship('Payment', backref='loan', lazy=True, cascade='all, delete-orphan')

    @property
    def total_interest(self):
        return self.loan_amount * (self.interest_rate / 100) * self.loan_term

    @property
    def total_due(self):
        return self.loan_amount + self.total_interest

    @property
    def total_paid(self):
        return sum(p.amount_paid for p in self.payments)

    @property
    def remaining_balance(self):
        return max(0, self.total_due - self.total_paid)

    @property
    def monthly_payment(self):
        return self.total_due / self.loan_term if self.loan_term > 0 else 0

class Payment(db.Model):
    __tablename__ = 'payments'
    payment_id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loans.loan_id'), nullable=False)
    amount_paid = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.Date, default=date.today)
    penalty = db.Column(db.Float, default=0.0)
    is_late = db.Column(db.Boolean, default=False)
    recorded_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    notes = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Expense(db.Model):
    __tablename__ = 'expenses'
    expense_id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    expense_date = db.Column(db.Date, default=date.today)
    recorded_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminLog(db.Model):
    __tablename__ = 'admin_logs'
    log_id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(500), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

# ─────────────────────────────
# HELPERS
# ─────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        if session.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def log_action(admin_id, action):
    log = AdminLog(admin_id=admin_id, action=action)
    db.session.add(log)
    db.session.commit()

def update_loan_status(loan):
    if loan.remaining_balance <= 0:
        loan.status = 'paid'
    elif loan.due_date and date.today() > loan.due_date:
        loan.status = 'overdue'
    else:
        loan.status = 'ongoing'

# ─────────────────────────────
# ROUTES
# ─────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

# AUTH

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user and check_password_hash(user.password, data.get('password')):
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        log_action(user.user_id, f"User '{user.username}' logged in")
        return jsonify({'success': True})

    return jsonify({'success': False}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    log_action(session['user_id'], f"User '{session['username']}' logged out")
    session.clear()
    return jsonify({'success': True})

# DASHBOARD (FIXED ✅)

@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    total_consumers = Consumer.query.count()
    total_loans = Loan.query.count()
    active_loans = Loan.query.filter_by(status='ongoing').count()
    overdue_loans = Loan.query.filter_by(status='overdue').count()
    paid_loans = Loan.query.filter_by(status='paid').count()

    total_disbursed = db.session.query(
        db.func.sum(Loan.loan_amount)
    ).scalar() or 0

    total_paid = db.session.query(
        db.func.sum(Payment.amount_paid)
    ).scalar() or 0

    total_expenses = db.session.query(
        db.func.sum(Expense.amount)
    ).scalar() or 0

    profit = total_paid - total_disbursed - total_expenses

    return jsonify({
        'total_consumers': total_consumers,
        'total_loans': total_loans,
        'active_loans': active_loans,
        'overdue_loans': overdue_loans,
        'paid_loans': paid_loans,
        'total_disbursed': float(total_disbursed),
        'total_paid': float(total_paid),
        'total_expenses': float(total_expenses),
        'profit': float(profit)
    })

# ─────────────────────────────
# INIT DB
# ─────────────────────────────

with app.app_context():
    db.create_all()

# ─────────────────────────────
# RUN
# ─────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
