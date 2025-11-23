from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, DateField, TimeField, SelectField
from wtforms.validators import InputRequired, NumberRange
from datetime import datetime, date, time
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign in')


class TransactionForm(FlaskForm):
    amount = DecimalField(
        'Amount (₹)', places=2,
        validators=[InputRequired(message="Amount is required"),
                    NumberRange(min=0, message="Amount must be positive")]
    )

    description = StringField('What was it for?', validators=[InputRequired(message="Description required")])

    # 🔸 Dropdown for category
    category = SelectField(
        'Category',
        choices=[
            ('Food', 'Food'),
            ('Travel', 'Travel'),
            ('Bills', 'Bills'),
            ('Shopping', 'Shopping'),
            ('Health', 'Health'),
            ('Entertainment', 'Entertainment'),
            ('Savings', 'Savings'),
            ('Other', 'Other')
        ],
        default='Other'
    )

    # 🔸 Separate date and time inputs
    date = DateField('Date', default=date.today, format='%Y-%m-%d')
    time = TimeField('Time', default=datetime.now().time, format='%H:%M')

    submit = SubmitField('Save')


class RecurringForm(FlaskForm):
    amount = DecimalField('Amount (₹)', places=2,
                          validators=[InputRequired(message="Amount required"), NumberRange(min=0)])
    description = StringField('Description', validators=[InputRequired()])
    category = SelectField(
        'Category',
        choices=[
            ('Food', 'Food'),
            ('Travel', 'Travel'),
            ('Bills', 'Bills'),
            ('Shopping', 'Shopping'),
            ('Health', 'Health'),
            ('Entertainment', 'Entertainment'),
            ('Savings', 'Savings'),
            ('Other', 'Other')
        ],
        default='Other'
    )

    # separate date and time inputs
    start_date = DateField('Start Date', default=date.today, format='%Y-%m-%d')
    start_time = TimeField('Start Time', default=datetime.now().time, format='%H:%M')

    # frequency selector
    frequency = SelectField('Frequency', choices=[('monthly','Monthly'), ('yearly','Yearly')], default='monthly')

    submit = SubmitField('Save Recurring Rule')