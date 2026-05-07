# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SubmitLogForm(FlaskForm):
    src_ip = StringField('Source IP', validators=[DataRequired()])
    username = StringField('Username', validators=[Optional()])
    event_type = SelectField('Event Type', choices=[
        ('login', 'Login'), ('web_request', 'Web Request'),
        ('error', 'Error'), ('other', 'Other')
    ], validators=[DataRequired()])
    status = SelectField('Status', choices=[
        ('success', 'Success'), ('failed', 'Failed'), ('error', 'Error')
    ], validators=[DataRequired()])
    details = TextAreaField('Details')
    submit = SubmitField('Submit Log')