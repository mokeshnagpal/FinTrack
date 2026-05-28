from datetime import datetime, timedelta, timezone

from flask_wtf import FlaskForm
from wtforms import (
    DateField,
    DecimalField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TimeField,
)
from wtforms.validators import DataRequired, EqualTo, InputRequired, Length, NumberRange
from wtforms.validators import Regexp


CATEGORY_CHOICES = [
    ('Food', 'Food'),
    ('Travel', 'Travel'),
    ('Bills', 'Bills'),
    ('Shopping', 'Shopping'),
    ('Health', 'Health'),
    ('Entertainment', 'Entertainment'),
    ('Savings', 'Savings'),
    ('Other', 'Other'),
]

STRONG_PASSWORD_MESSAGE = (
    'Use more than 6 characters with at least 1 uppercase letter, '
    '1 lowercase letter, and 1 number'
)
STRONG_PASSWORD_PATTERN = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{7,128}$'
EMAIL_PATTERN = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'

IST = timezone(timedelta(hours=5, minutes=30))


def today_ist():
    return datetime.now(IST).date()


def current_time_ist():
    return datetime.now(IST).time().replace(second=0, microsecond=0)


class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(max=120, message='Email is too long'),
            Regexp(EMAIL_PATTERN, message='Enter a valid email address'),
        ],
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(max=128, message='Password is too long'),
        ],
    )
    submit = SubmitField('Sign in')


class ViewPasswordForm(FlaskForm):
    password = PasswordField(
        'New view-only password',
        validators=[
            DataRequired(message='Password is required'),
            Regexp(STRONG_PASSWORD_PATTERN, message=STRONG_PASSWORD_MESSAGE),
        ],
    )
    confirm_password = PasswordField(
        'Confirm password',
        validators=[
            DataRequired(message='Please confirm the password'),
            EqualTo('password', message='Passwords must match'),
        ],
    )
    submit = SubmitField('Update View-only Password')


class ViewPasswordRevealForm(FlaskForm):
    current_password = PasswordField(
        'Type current view-only password',
        validators=[
            DataRequired(message='Current view-only password is required'),
            Length(max=128, message='Password is too long'),
        ],
    )
    submit = SubmitField('Show Password')


class CategoryForm(FlaskForm):
    name = StringField(
        'Category name',
        validators=[
            DataRequired(message='Category name is required'),
            Length(min=2, max=40, message='Use 2 to 40 characters'),
            Regexp(
                r'^[a-zA-Z0-9 &()./_-]+$',
                message='Use letters, numbers, spaces, and simple punctuation only',
            ),
        ],
    )
    submit = SubmitField('Add Category')


class ChangeUsernameForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(max=120, message='Email is too long'),
            Regexp(EMAIL_PATTERN, message='Enter a valid email address'),
        ],
    )
    submit = SubmitField('Update Username')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        'Current password',
        validators=[
            DataRequired(message='Current password is required'),
            Length(max=128, message='Password is too long'),
        ],
    )
    password = PasswordField(
        'New password',
        validators=[
            DataRequired(message='New password is required'),
            Regexp(STRONG_PASSWORD_PATTERN, message=STRONG_PASSWORD_MESSAGE),
        ],
    )
    confirm_password = PasswordField(
        'Confirm password',
        validators=[
            DataRequired(message='Please confirm the password'),
            EqualTo('password', message='Passwords must match'),
        ],
    )
    submit = SubmitField('Update Password')


class TransactionForm(FlaskForm):
    amount = DecimalField(
        'Amount (Rs.)',
        places=2,
        validators=[
            InputRequired(message='Amount is required'),
            NumberRange(min=0.01, max=999999999, message='Amount must be between 0.01 and 999999999'),
        ],
    )
    description = StringField(
        'What was it for?',
        validators=[
            InputRequired(message='Description required'),
            Length(max=120, message='Use 120 characters or fewer'),
        ],
    )
    category = SelectField('Category', choices=CATEGORY_CHOICES, default='Other')
    date = DateField(
        'Date (IST)',
        default=today_ist,
        format='%Y-%m-%d',
        validators=[DataRequired(message='Date is required')],
    )
    time = TimeField(
        'Time (IST)',
        default=current_time_ist,
        format='%H:%M',
        validators=[DataRequired(message='Time is required')],
    )
    submit = SubmitField('Save')


class RecurringForm(FlaskForm):
    amount = DecimalField(
        'Amount (Rs.)',
        places=2,
        validators=[
            InputRequired(message='Amount required'),
            NumberRange(min=0.01, max=999999999, message='Amount must be between 0.01 and 999999999'),
        ],
    )
    description = StringField(
        'Description',
        validators=[
            InputRequired(message='Description required'),
            Length(max=120, message='Use 120 characters or fewer'),
        ],
    )
    category = SelectField('Category', choices=CATEGORY_CHOICES, default='Other')
    start_date = DateField(
        'Start Date (IST)',
        default=today_ist,
        format='%Y-%m-%d',
        validators=[DataRequired(message='Start date is required')],
    )
    start_time = TimeField(
        'Start Time (IST)',
        default=current_time_ist,
        format='%H:%M',
        validators=[DataRequired(message='Start time is required')],
    )
    frequency = SelectField(
        'Frequency',
        choices=[('monthly', 'Monthly'), ('yearly', 'Yearly')],
        default='monthly',
    )
    submit = SubmitField('Save Recurring Rule')
