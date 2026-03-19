from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'loan_system_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loan_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ─────────────────────────────────────────────
# DATABASE MODELS
# ─────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    user_id     = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(80), unique=True, nullable=False)
    password    = db.Column(db.String(200), nullable=False)
    role        = db.Column(db.String(20), default='staff')  # 'admin' or 'staff'
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    logs        = db.relationship('AdminLog', backref='user', lazy=True)

class Consumer(db.Model):
    __tablename__ = 'consumers'
    consumer_id = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), nullable=False)
    contact     = db.Column(db.String(20))
    address     = db.Column(db.String(255))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    loans       = db.relationship('Loan', backref='consumer', lazy=True, cascade='all, delete-orphan')

class Loan(db.Model):
    __tablename__ = 'loans'
    loan_id       = db.Column(db.Integer, primary_key=True)
    consumer_id   = db.Column(db.Integer, db.ForeignKey('consumers.consumer_id'), nullable=False)
    loan_amount   = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)   # monthly %
    loan_term     = db.Column(db.Integer, nullable=False) # months
    start_date    = db.Column(db.Date, default=date.today)
    due_date      = db.Column(db.Date)
    status        = db.Column(db.String(20), default='ongoing')  # ongoing/paid/overdue
    penalty_rate  = db.Column(db.Float, default=2.0)  # % per month late
    approved_by   = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    payments      = db.relationship('Payment', backref='loan', lazy=True, cascade='all, delete-orphan')

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
    payment_id   = db.Column(db.Integer, primary_key=True)
    loan_id      = db.Column(db.Integer, db.ForeignKey('loans.loan_id'), nullable=False)
    amount_paid  = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.Date, default=date.today)
    penalty      = db.Column(db.Float, default=0.0)
    is_late      = db.Column(db.Boolean, default=False)
    recorded_by  = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    notes        = db.Column(db.String(255))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

class Expense(db.Model):
    __tablename__ = 'expenses'
    expense_id   = db.Column(db.Integer, primary_key=True)
    description  = db.Column(db.String(255), nullable=False)
    amount       = db.Column(db.Float, nullable=False)
    expense_date = db.Column(db.Date, default=date.today)
    recorded_by  = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

class AdminLog(db.Model):
    __tablename__ = 'admin_logs'
    log_id    = db.Column(db.Integer, primary_key=True)
    admin_id  = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action    = db.Column(db.String(500), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

# ─────────────────────────────────────────────
# HELPERS & DECORATORS
# ─────────────────────────────────────────────

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

# ─────────────────────────────────────────────
# ROUTES — PAGES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html')
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('index.html')

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        log_action(user.user_id, f"User '{user.username}' logged in")
        return jsonify({'success': True, 'role': user.role, 'username': user.username})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    log_action(session['user_id'], f"User '{session['username']}' logged out")
    session.clear()
    return jsonify({'success': True})

@app.route('/api/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'role': session.get('role'), 'username': session.get('username')})
    return jsonify({'logged_in': False})

# ─────────────────────────────────────────────
# USER MANAGEMENT ROUTES
# ─────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'user_id': u.user_id, 'username': u.username,
        'role': u.role, 'created_at': str(u.created_at)
    } for u in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def add_user():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    user = User(
        username=data['username'],
        password=generate_password_hash(data['password']),
        role=data.get('role', 'staff')
    )
    db.session.add(user)
    db.session.commit()
    log_action(session['user_id'], f"Created user '{data['username']}' with role '{user.role}'")
    return jsonify({'success': True, 'user_id': user.user_id})

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    user = User.query.get_or_404(uid)
    db.session.delete(user)
    db.session.commit()
    log_action(session['user_id'], f"Deleted user '{user.username}'")
    return jsonify({'success': True})

# ─────────────────────────────────────────────
# CONSUMER ROUTES
# ─────────────────────────────────────────────

@app.route('/api/consumers', methods=['GET'])
@login_required
def get_consumers():
    search = request.args.get('search', '')
    query = Consumer.query
    if search:
        query = query.filter(Consumer.name.ilike(f'%{search}%'))
    consumers = query.order_by(Consumer.name).all()
    return jsonify([{
        'consumer_id': c.consumer_id, 'name': c.name,
        'contact': c.contact, 'address': c.address,
        'loan_count': len(c.loans),
        'created_at': str(c.created_at)
    } for c in consumers])

@app.route('/api/consumers', methods=['POST'])
@login_required
def add_consumer():
    data = request.get_json()
    consumer = Consumer(name=data['name'], contact=data.get('contact',''), address=data.get('address',''))
    db.session.add(consumer)
    db.session.commit()
    log_action(session['user_id'], f"Added consumer '{data['name']}'")
    return jsonify({'success': True, 'consumer_id': consumer.consumer_id})

@app.route('/api/consumers/<int:cid>', methods=['PUT'])
@login_required
def update_consumer(cid):
    consumer = Consumer.query.get_or_404(cid)
    data = request.get_json()
    consumer.name    = data.get('name', consumer.name)
    consumer.contact = data.get('contact', consumer.contact)
    consumer.address = data.get('address', consumer.address)
    db.session.commit()
    log_action(session['user_id'], f"Updated consumer ID {cid} '{consumer.name}'")
    return jsonify({'success': True})

@app.route('/api/consumers/<int:cid>', methods=['DELETE'])
@admin_required
def delete_consumer(cid):
    consumer = Consumer.query.get_or_404(cid)
    name = consumer.name
    db.session.delete(consumer)
    db.session.commit()
    log_action(session['user_id'], f"Deleted consumer '{name}'")
    return jsonify({'success': True})

# ─────────────────────────────────────────────
# LOAN ROUTES
# ─────────────────────────────────────────────

@app.route('/api/loans', methods=['GET'])
@login_required
def get_loans():
    search  = request.args.get('search', '')
    status  = request.args.get('status', '')
    loans   = Loan.query.join(Consumer)
    if search:
        loans = loans.filter(Consumer.name.ilike(f'%{search}%'))
    if status:
        loans = loans.filter(Loan.status == status)
    loans = loans.order_by(Loan.created_at.desc()).all()

    for loan in loans:
        update_loan_status(loan)
    db.session.commit()

    return jsonify([{
        'loan_id': l.loan_id,
        'consumer_id': l.consumer_id,
        'consumer_name': l.consumer.name,
        'loan_amount': l.loan_amount,
        'interest_rate': l.interest_rate,
        'loan_term': l.loan_term,
        'total_interest': round(l.total_interest, 2),
        'total_due': round(l.total_due, 2),
        'total_paid': round(l.total_paid, 2),
        'remaining_balance': round(l.remaining_balance, 2),
        'monthly_payment': round(l.monthly_payment, 2),
        'status': l.status,
        'start_date': str(l.start_date),
        'due_date': str(l.due_date) if l.due_date else None,
        'penalty_rate': l.penalty_rate,
        'created_at': str(l.created_at)
    } for l in loans])

@app.route('/api/loans', methods=['POST'])
@login_required
def add_loan():
    data = request.get_json()
    start = date.today()
    due   = start + timedelta(days=30 * int(data['loan_term']))
    loan  = Loan(
        consumer_id   = data['consumer_id'],
        loan_amount   = float(data['loan_amount']),
        interest_rate = float(data['interest_rate']),
        loan_term     = int(data['loan_term']),
        start_date    = start,
        due_date      = due,
        penalty_rate  = float(data.get('penalty_rate', 2.0)),
        status        = 'ongoing',
        approved_by   = session['user_id']
    )
    db.session.add(loan)
    db.session.commit()
    log_action(session['user_id'], f"Created loan ID {loan.loan_id} for consumer ID {data['consumer_id']} — ₱{data['loan_amount']}")
    return jsonify({'success': True, 'loan_id': loan.loan_id})

@app.route('/api/loans/<int:lid>', methods=['DELETE'])
@admin_required
def delete_loan(lid):
    loan = Loan.query.get_or_404(lid)
    db.session.delete(loan)
    db.session.commit()
    log_action(session['user_id'], f"Deleted loan ID {lid}")
    return jsonify({'success': True})

# ─────────────────────────────────────────────
# PAYMENT ROUTES
# ─────────────────────────────────────────────

@app.route('/api/payments', methods=['GET'])
@login_required
def get_payments():
    loan_id = request.args.get('loan_id')
    search  = request.args.get('search', '')
    query   = Payment.query.join(Loan).join(Consumer)
    if loan_id:
        query = query.filter(Payment.loan_id == loan_id)
    if search:
        query = query.filter(Consumer.name.ilike(f'%{search}%'))
    payments = query.order_by(Payment.payment_date.desc()).all()
    return jsonify([{
        'payment_id': p.payment_id,
        'loan_id': p.loan_id,
        'consumer_name': p.loan.consumer.name,
        'amount_paid': p.amount_paid,
        'payment_date': str(p.payment_date),
        'penalty': p.penalty,
        'is_late': p.is_late,
        'notes': p.notes,
        'created_at': str(p.created_at)
    } for p in payments])

@app.route('/api/payments', methods=['POST'])
@login_required
def add_payment():
    data    = request.get_json()
    loan    = Loan.query.get_or_404(data['loan_id'])
    pay_date = datetime.strptime(data['payment_date'], '%Y-%m-%d').date()
    is_late = pay_date > loan.due_date if loan.due_date else False

    penalty = 0.0
    if is_late:
        months_late = max(1, (pay_date - loan.due_date).days // 30)
        penalty = loan.remaining_balance * (loan.penalty_rate / 100) * months_late

    payment = Payment(
        loan_id      = loan.loan_id,
        amount_paid  = float(data['amount_paid']),
        payment_date = pay_date,
        penalty      = round(penalty, 2),
        is_late      = is_late,
        recorded_by  = session['user_id'],
        notes        = data.get('notes', '')
    )
    db.session.add(payment)
    update_loan_status(loan)
    db.session.commit()
    log_action(session['user_id'], f"Recorded payment ₱{data['amount_paid']} for loan ID {loan.loan_id}{' (LATE)' if is_late else ''}")
    return jsonify({'success': True, 'payment_id': payment.payment_id, 'penalty': penalty, 'is_late': is_late})

@app.route('/api/payments/<int:pid>', methods=['DELETE'])
@admin_required
def delete_payment(pid):
    payment = Payment.query.get_or_404(pid)
    loan    = payment.loan
    db.session.delete(payment)
    update_loan_status(loan)
    db.session.commit()
    log_action(session['user_id'], f"Deleted payment ID {pid}")
    return jsonify({'success': True})

# ─────────────────────────────────────────────
# EXPENSE ROUTES
# ─────────────────────────────────────────────

@app.route('/api/expenses', methods=['GET'])
@login_required
def get_expenses():
    expenses = Expense.query.order_by(Expense.expense_date.desc()).all()
    return jsonify([{
        'expense_id': e.expense_id,
        'description': e.description,
        'amount': e.amount,
        'expense_date': str(e.expense_date),
        'created_at': str(e.created_at)
    } for e in expenses])

@app.route('/api/expenses', methods=['POST'])
@login_required
def add_expense():
    data = request.get_json()
    expense = Expense(
        description  = data['description'],
        amount       = float(data['amount']),
        expense_date = datetime.strptime(data['expense_date'], '%Y-%m-%d').date(),
        recorded_by  = session['user_id']
    )
    db.session.add(expense)
    db.session.commit()
    log_action(session['user_id'], f"Added expense '{data['description']}' — ₱{data['amount']}")
    return jsonify({'success': True})

@app.route('/api/expenses/<int:eid>', methods=['DELETE'])
@admin_required
def delete_expense(eid):
    expense = Expense.query.get_or_404(eid)
    db.session.delete(expense)
    db.session.commit()
    log_action(session['user_id'], f"Deleted expense ID {eid}")
    return jsonify({'success': True})

# ─────────────────────────────────────────────
# PROFIT & DASHBOARD ROUTES
# ─────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    total_consumers   = Consumer.query.count()
    total_loans       = Loan.query.count()
    active_loans      = Loan.query.filter_by(status='ongoing').count()
    overdue_loans     = Loan.query.filter_by(status='overdue').count()
    paid_loans        = Loan.query.filter_by(status='paid').count()
    total_disbursed   = db.session.query