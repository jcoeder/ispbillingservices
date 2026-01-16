# app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    accounts = db.relationship('Account', backref='vendor', lazy=True, cascade='all, delete-orphan')

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(100), nullable=False)  # e.g., account number
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=False)
    services = db.relationship('Service', backref='account', lazy=True, cascade='all, delete-orphan')

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    type = db.Column(db.Enum('phone', 'sip', 'internet', 'wan', name='service_type'), nullable=False)
    service_id = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    a_location = db.Column(db.String(200), nullable=True)  # A location, optional
    z_location = db.Column(db.String(200), nullable=True)  # Z location, optional
    account_number = db.Column(db.String(100), nullable=True)  # Defaults to account.account_id, editable
    description = db.Column(db.Text, nullable=True)

# Decorator for admin required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not User.query.get(session['user_id']).is_admin:
            flash('Admin access required.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        user = User(username=username, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('User added.')
        return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/vendors', methods=['GET', 'POST'])
def manage_vendors():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        vendor = Vendor(name=name)
        db.session.add(vendor)
        db.session.commit()
        flash('Vendor added.')
        return redirect(url_for('manage_vendors'))
    vendors = Vendor.query.all()
    return render_template('vendors.html', vendors=vendors)

@app.route('/vendors/<int:vendor_id>/accounts', methods=['GET', 'POST'])
def manage_accounts(vendor_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vendor = Vendor.query.get_or_404(vendor_id)
    if request.method == 'POST':
        account_id = request.form['account_id']
        account = Account(account_id=account_id, vendor_id=vendor_id)
        db.session.add(account)
        db.session.commit()
        flash('Account added.')
        return redirect(url_for('manage_accounts', vendor_id=vendor_id))
    accounts = Account.query.filter_by(vendor_id=vendor_id).all()
    return render_template('accounts.html', vendor=vendor, accounts=accounts)

@app.route('/accounts/<int:account_id>/services', methods=['GET', 'POST'])
def manage_services(account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    account = Account.query.get_or_404(account_id)
    if request.method == 'POST':
        type_ = request.form['type']
        service_id = request.form.get('service_id')
        phone_number = request.form.get('phone_number')
        a_location = request.form.get('a_location')
        z_location = request.form.get('z_location')
        account_number = request.form.get('account_number') or account.account_id  # Default to account's account_id
        description = request.form.get('description')
        service = Service(
            account_id=account_id,
            type=type_,
            service_id=service_id,
            phone_number=phone_number,
            a_location=a_location,
            z_location=z_location,
            account_number=account_number,
            description=description
        )
        db.session.add(service)
        db.session.commit()
        flash('Service added.')
        return redirect(url_for('manage_services', account_id=account_id))
    services = Service.query.filter_by(account_id=account_id).all()
    return render_template('services.html', account=account, services=services)

@app.route('/vendors/<int:vendor_id>/all_services')
def all_services(vendor_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vendor = Vendor.query.get_or_404(vendor_id)
    # Get all services for accounts under this vendor
    services = Service.query.join(Account).filter(Account.vendor_id == vendor_id).all()
    accounts = Account.query.filter_by(vendor_id=vendor_id).all()  # For filtering dropdown
    selected_account_id = request.args.get('account_id', type=int)
    if selected_account_id:
        services = [s for s in services if s.account_id == selected_account_id]
    return render_template('all_services.html', vendor=vendor, services=services, accounts=accounts, selected_account_id=selected_account_id)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
def edit_service(service_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.type = request.form['type']
        service.service_id = request.form.get('service_id')
        service.phone_number = request.form.get('phone_number')
        service.a_location = request.form.get('a_location')
        service.z_location = request.form.get('z_location')
        service.account_number = request.form.get('account_number')
        service.description = request.form.get('description')
        db.session.commit()
        flash('Service updated.')
        return redirect(url_for('manage_services', account_id=service.account_id))
    return render_template('edit_service.html', service=service)

@app.route('/services/<int:service_id>/delete')
def delete_service(service_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted.')
    return redirect(url_for('manage_services', account_id=service.account_id))

# Seed initial admin
def seed_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('adminpassword')  # Change this!
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_admin()
    app.run(debug=True)