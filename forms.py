from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DecimalField, SubmitField, BooleanField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
from models import User  # Make sure to import your User model
from werkzeug.security import generate_password_hash


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be 8+ characters")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    membership_type = SelectField('Membership Type', choices=[
        ('diaspora', 'Diaspora Member'),
        ('urban', 'Urban Zimbabwe'),
        ('rural', 'Rural Zimbabwe')
    ], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class LoanApplicationForm(FlaskForm):
    loan_type = SelectField('Loan Type', choices=[
        ('personal', 'Personal Loan'),
        ('business', 'Business Loan'),
        ('education', 'Education Loan'),
        ('emergency', 'Emergency Loan'),
        ('home', 'Home Improvement')
    ], validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[
        DataRequired(),
        NumberRange(min=100, message="Minimum loan amount is $100")
    ])
    purpose = TextAreaField('Purpose', validators=[
        DataRequired(),
        Length(max=500)
    ])
    duration = IntegerField('Duration (months)', validators=[
        DataRequired(),
        NumberRange(min=1, max=60, message="Duration must be 1-60 months")
    ])
    submit = SubmitField('Apply')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be 8+ characters")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    membership_type = SelectField('Membership Type', choices=[
        ('diaspora', 'Diaspora Member'),
        ('urban', 'Urban Zimbabwe'),
        ('rural', 'Rural Zimbabwe')
    ], validators=[DataRequired()])
    is_admin = BooleanField('Is Admin', default=False)  # Properly defined with default
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')