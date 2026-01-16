# app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
import os
import pdfplumber  # For PDF text extraction

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/opt/isp-circuit-invoice-tracker/uploads'  # Directory for uploaded PDFs
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}  # Only allow PDF uploads

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.context_processor
def inject_current_user():
    if 'user_id' in session:
        return {'current_user': User.query.get(session['user_id'])}
    return {'current_user': None}

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to extract text from PDF
def extract_pdf_text(filepath):
    text = ""
    try:
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
    return text

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Increased from 128 to 256
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    billing_accounts = db.relationship('BillingAccount', backref='vendor', lazy=True, cascade='all, delete-orphan')

class BillingAccount(db.Model):  # Renamed from Account to BillingAccount
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(100), nullable=False)  # e.g., billing account number
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=False)
    services = db.relationship('Service', backref='billing_account', lazy=True, cascade='all, delete-orphan')
    invoices = db.relationship('Invoice', backref='billing_account', lazy=True, cascade='all, delete-orphan')

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    billing_account_id = db.Column(db.Integer, db.ForeignKey('billing_account.id'), nullable=False)
    service_id = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    a_location = db.Column(db.String(200), nullable=True)  # A location, optional
    z_location = db.Column(db.String(200), nullable=True)  # Z location, optional
    account_number = db.Column(db.String(100), nullable=True)  # Defaults to billing_account.account_id, editable
    description = db.Column(db.Text, nullable=True)  # Now the first column in displays

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    billing_account_id = db.Column(db.Integer, db.ForeignKey('billing_account.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    parsed_text = db.Column(db.Text, nullable=True)  # Extracted text for searching
    uploaded_at = db.Column(db.DateTime, default=db.func.now())

# Seed initial admin on app startup (runs after models are defined)
def seed_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_password = os.environ.get('ADMIN_PASSWORD', 'adminpassword')
            admin = User(username='admin', is_admin=True)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            print(f"Admin user created with password: {admin_password}")
            print("Please change the default password after first login!")

seed_admin()  # Call seeding after models are defined

# Decorator for admin required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not User.query.get(session['user_id']).is_admin:
            flash('Admin access required.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes (unchanged from your version, as they look fine)
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

@app.route('/vendors/<int:vendor_id>/billing_accounts', methods=['GET', 'POST'])  # Updated route name
def manage_billing_accounts(vendor_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vendor = Vendor.query.get_or_404(vendor_id)
    if request.method == 'POST':
        account_id = request.form['account_id']
        billing_account = BillingAccount(account_id=account_id, vendor_id=vendor_id)
        db.session.add(billing_account)
        db.session.commit()
        flash('Billing account added.')
        return redirect(url_for('manage_billing_accounts', vendor_id=vendor_id))
    billing_accounts = BillingAccount.query.filter_by(vendor_id=vendor_id).all()
    return render_template('billing_accounts.html', vendor=vendor, billing_accounts=billing_accounts)

@app.route('/billing_accounts/<int:billing_account_id>/services', methods=['GET', 'POST'])  # Updated route
def manage_services(billing_account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    billing_account = BillingAccount.query.get_or_404(billing_account_id)
    if request.method == 'POST':
        service_id = request.form.get('service_id')
        phone_number = request.form.get('phone_number')
        a_location = request.form.get('a_location')
        z_location = request.form.get('z_location')
        account_number = request.form.get('account_number') or billing_account.account_id
        description = request.form.get('description')
        service = Service(
            billing_account_id=billing_account_id,
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
        return redirect(url_for('manage_services', billing_account_id=billing_account_id))
    services = Service.query.filter_by(billing_account_id=billing_account_id).all()
    return render_template('services.html', billing_account=billing_account, services=services)

@app.route('/vendors/<int:vendor_id>/all_services')
def all_services(vendor_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vendor = Vendor.query.get_or_404(vendor_id)
    services = Service.query.join(BillingAccount).filter(BillingAccount.vendor_id == vendor_id).all()
    billing_accounts = BillingAccount.query.filter_by(vendor_id=vendor_id).all()
    selected_billing_account_id = request.args.get('billing_account_id', type=int)
    if selected_billing_account_id:
        services = [s for s in services if s.billing_account_id == selected_billing_account_id]
    return render_template('all_services.html', vendor=vendor, services=services, billing_accounts=billing_accounts, selected_billing_account_id=selected_billing_account_id)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
def edit_service(service_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.service_id = request.form.get('service_id')
        service.phone_number = request.form.get('phone_number')
        service.a_location = request.form.get('a_location')
        service.z_location = request.form.get('z_location')
        service.account_number = request.form.get('account_number')
        service.description = request.form.get('description')
        db.session.commit()
        flash('Service updated.')
        return redirect(url_for('manage_services', billing_account_id=service.billing_account_id))
    return render_template('edit_service.html', service=service)

@app.route('/services/<int:service_id>/delete', methods=['POST'])
def delete_service(service_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted.')
    return redirect(url_for('manage_services', billing_account_id=service.billing_account_id))

@app.route('/billing_accounts/<int:billing_account_id>/invoices', methods=['GET', 'POST'])
def manage_invoices(billing_account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    billing_account = BillingAccount.query.get_or_404(billing_account_id)
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            parsed_text = extract_pdf_text(filepath)
            invoice = Invoice(
                billing_account_id=billing_account_id,
                filename=filename,
                filepath=filepath,
                parsed_text=parsed_text
            )
            db.session.add(invoice)
            db.session.commit()
            flash('Invoice uploaded and processed.')
            return redirect(url_for('manage_invoices', billing_account_id=billing_account_id))
    invoices = Invoice.query.filter_by(billing_account_id=billing_account_id).all()
    return render_template('invoices.html', billing_account=billing_account, invoices=invoices)

@app.route('/search', methods=['GET', 'POST'])
def search_invoices():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    query = request.args.get('q', '')
    results = []
    if query:
        results = Invoice.query.filter(Invoice.parsed_text.ilike(f'%{query}%')).all()
    return render_template('search.html', query=query, results=results)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)