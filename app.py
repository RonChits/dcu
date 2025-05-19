from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from config import Config
from forms import RegistrationForm, LoginForm, LoanApplicationForm
from extensions import db, login_manager
from models import User, Loan, Document
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
import os
from wtforms import StringField, PasswordField, SelectField, DecimalField, SubmitField, BooleanField, TextAreaField, IntegerField
from werkzeug.security import check_password_hash
from flask import Blueprint
from templates.auth.routes import auth_bp
from datetime import datetime


app = Flask(__name__, template_folder="templates")
app.config.from_object(Config)

app.register_blueprint(auth_bp, url_prefix='/auth')
# Initialize extensions
db.init_app(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def initialize_database():
    with app.app_context():
        # Create all tables first
        db.create_all()

        # Then check if admin exists
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                username='admin',
                first_name='Admin',
                last_name='User',
                email='admin@example.com',
                phone='1234567890Ro',
                password=generate_password_hash('1234567890Ro'),
                membership_type='urban',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created!")


# Initialize the database when the app starts
initialize_database()


@app.template_filter('time_since')
def time_since(dt):
    if dt:
        delta = datetime.utcnow() - dt
        return delta.days // 30
    return 0


# Routes


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)  # Forbidden if not admin

    # Get all users ordered by registration date (newest first)
    users = User.query.order_by(User.member_since.desc()).all()

    return render_template('admin/users.html', users=users)


management_team = [
    {'name': 'Blessed Kapesa', 'position': 'Chairman'},
    {'name': 'Alexander Dhomani', 'position': 'Vice Chairman'},
    {'name': 'Lisa Govera', 'position': 'Secretary'},
    {'name': 'Josphat Madziyire', 'position': 'Treasurer'}
]

board_members = [
    {'name': 'Joyce Dhomhani', 'position': 'Board Member'},
    {'name': 'Thelma Murakasha', 'position': 'Board Member'},
    {'name': 'Farai Mushawetu', 'position': 'Board Member'}
]


@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        abort(403)

    form = RegistrationForm()

    # Remove is_admin field for non-admin users
    if not current_user.is_admin:
        del form.is_admin

    if form.validate_on_submit():
        try:
            user = User(
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                email=form.email.data,
                phone=form.phone.data,
                password=generate_password_hash(form.password.data),
                membership_type=form.membership_type.data,
                is_admin=form.is_admin.data if current_user.is_admin else False
            )
            db.session.add(user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_users'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists!', 'danger')

    return render_template('admin/create_user.html', form=form)


@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)

    if form.validate_on_submit():
        try:
            form.populate_obj(user)
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_users'))
        except IntegrityError:
            db.session.rollback()
            flash('Error updating user!', 'danger')

    return render_template('admin/edit_user.html', form=form, user=user)


@app.route('/admin/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/open-account', methods=['GET', 'POST'])
@login_required
def open_account():
    if request.method == 'POST':
        try:
            # Determine account type from form submission
            account_type = request.form.get('account_type')

            # Update user's account status in database
            if account_type == 'savings':
                current_user.savings_balance += 50  # Initial deposit
                flash('Savings account opened successfully with $50 initial deposit!', 'success')
            elif account_type == 'shares':
                current_user.shares += 5  # Initial shares
                flash('Share account opened successfully with 5 initial shares!', 'success')

            db.session.commit()
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Error opening account. Please try again.', 'danger')

    return render_template('dashboard/open_account.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    # Get loans with user information
    loans = db.session.query(
        Loan,
        User.username,
        User.email
    ).join(
        User, Loan.user_id == User.id
    ).order_by(
        Loan.date_applied.desc()
    ).all()

    # Get all users
    users = User.query.order_by(User.member_since.desc()).all()

    print(f"Debug: Found {len(users)} users")  # Debug output

    return render_template('admin/dashboard.html',
                           loans=loans,
                           users=users)


@app.route('/about')
def about():
    return render_template('about.html', team=management_team)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # Basic implementation - you'll want to expand this
    if request.method == 'POST':
        email = request.form.get('email')
        # Add your password reset logic here
        flash('If an account exists with that email, a reset link has been sent', 'info')
        return redirect(url_for('login'))
    return render_template('auth/reset_password.html')  # You'll need to create this template


@app.route('/membership')
def membership():
    membership_options = [
        {'type': 'Diaspora', 'fee': 30, 'shares': 10, 'deposit': 50},
        {'type': 'Urban Zimbabwe', 'fee': 20, 'shares': 5, 'deposit': 30},
        {'type': 'Rural Zimbabwe', 'fee': 10, 'shares': 2, 'deposit': 10}
    ]
    return render_template('membership.html', options=membership_options)


@app.route('/apply-loan', methods=['GET', 'POST'])
@login_required
def apply_loan():
    form = LoanApplicationForm()

    # Define interest rates for different loan types
    interest_rates = {
        'personal': 0.12,  # 12%
        'business': 0.15,  # 15%
        'education': 0.10,  # 10%
        'emergency': 0.20,  # 20%
        'home': 0.08  # 8%
    }

    if form.validate_on_submit():
        try:
            # Get the appropriate interest rate
            interest_rate = interest_rates.get(form.loan_type.data, 0.12)  # Default to 12%

            loan = Loan(
                loan_type=form.loan_type.data,
                amount=form.amount.data,
                interest_rate=interest_rate,  # This was missing
                status='Pending',
                date_applied=datetime.utcnow(),
                user_id=current_user.id
            )

            db.session.add(loan)
            db.session.commit()
            flash('Loan application submitted successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting loan application: {str(e)}', 'danger')

    # Pass interest rates to template to display them
    return render_template('dashboard/apply_loan.html',
                           form=form,
                           interest_rates=interest_rates)


@app.route('/admin/loans')
@login_required
def admin_loans():
    if not current_user.is_admin:
        abort(403)  # Forbidden if not admin

    # Get all loans with user information
    loans = Loan.query.join(User).add_columns(
        Loan.id,
        User.username,
        User.email,
        Loan.loan_type,
        Loan.amount,
        Loan.interest_rate,
        Loan.status,
        Loan.date_applied
    ).order_by(Loan.date_applied.desc()).all()

    return render_template('admin/loans.html', loans=loans)


@app.route('/admin/approve-loan/<int:loan_id>')
@login_required
def approve_loan(loan_id):
    if not current_user.is_admin:
        abort(403)

    loan = Loan.query.get_or_404(loan_id)
    loan.status = 'Approved'
    db.session.commit()

    flash(f'Loan #{loan_id} has been approved', 'success')
    return redirect(url_for('admin_loans'))


@app.route('/admin/reject-loan/<int:loan_id>')
@login_required
def reject_loan(loan_id):
    if not current_user.is_admin:
        abort(403)

    loan = Loan.query.get_or_404(loan_id)
    loan.status = 'Rejected'
    db.session.commit()

    flash(f'Loan #{loan_id} has been rejected', 'warning')
    return redirect(url_for('admin_loans'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            # Generate a username from first & last name
            username = f"{form.first_name.data.lower()}_{form.last_name.data.lower()}"

            # Create user with hashed password
            user = User(
                username=username,  # Required if your User model has this field
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                email=form.email.data,
                phone=form.phone.data,
                password=generate_password_hash(form.password.data),  # Hashes password
                membership_type=form.membership_type.data,
                # Set default values for other required fields:
                member_since=datetime.utcnow(),
                is_admin=False,
                shares=0,
                monthly_deposit=0.0,
                savings_balance=0.0
            )

            db.session.add(user)
            db.session.commit()

            flash('Registration successful! Welcome.', 'success')
            return redirect(url_for('login'))

        except IntegrityError as e:
            db.session.rollback()
            if "UNIQUE constraint failed: user.email" in str(e):
                flash('Email already in use. Please use a different email.', 'danger')
            elif "UNIQUE constraint failed: user.username" in str(e):
                flash('Username already exists. Please try a different name.', 'danger')
            else:
                flash('Registration failed. Please try again.', 'danger')

    return render_template('auth/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # If already logged in, redirect to appropriate dashboard
        return redirect(url_for('admin_loans' if current_user.is_admin else 'dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        # Hardcoded admin credentials
        ADMIN_EMAIL = 'admin@example.com'
        ADMIN_PASSWORD = '1234567890Ro'

        # Check if it's the admin trying to login
        if form.email.data == ADMIN_EMAIL and form.password.data == ADMIN_PASSWORD:
            admin = User.query.filter_by(email=ADMIN_EMAIL).first()
            if admin:
                login_user(admin)
                return redirect(url_for('admin_loans'))
            else:
                flash('Admin account not found in database', 'danger')
                return redirect(url_for('login'))

        # Normal user login flow
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid email or password', 'danger')

    return render_template('auth/login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# In app.py or your loans blueprint file
@app.route('/loans')  # or @bp.route if using blueprints
def loans():
    return render_template('loans.html')


# In app.py or your routes file
@app.route('/savings')  # Basic route without blueprint
def savings():
    return render_template('savings.html')


# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    loans = Loan.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard/index.html', loans=loans)


if __name__ == '__main__':
    app.run(debug=True)
