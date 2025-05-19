from flask import render_template, redirect, url_for, flash, request
from werkzeug.security import check_password_hash, generate_password_hash
from . import auth_bp
from models import User
from flask_login import current_user
from forms import LoginForm
from models import db
from forms import RegistrationForm
from flask_login import login_required


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()  # If using Flask-WTF

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check email/password', 'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Calculate initial values based on membership type
        membership_type = form.membership_type.data
        shares = 10 if membership_type == 'diaspora' else (5 if membership_type == 'urban' else 2)
        monthly_deposit = 50 if membership_type == 'diaspora' else (30 if membership_type == 'urban' else 10)

        # Create new user with all required fields
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            membership_type=form.membership_type.data,
            shares=10 if form.membership_type.data == 'diaspora' else (
                5 if form.membership_type.data == 'urban' else 2),
            monthly_deposit=50 if form.membership_type.data == 'diaspora' else (
                30 if form.membership_type.data == 'urban' else 10)
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Registration successful!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists!', 'danger')

    return render_template('auth/register.html', form=form)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # Add your password reset logic here
    return render_template('auth/reset_password.html')


@auth_bp.route('/dashboard')
@login_required  # Ensures only logged-in users can access
def dashboard():
    return render_template('dashboard/index.html', user=current_user)