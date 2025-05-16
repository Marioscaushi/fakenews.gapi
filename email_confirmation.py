from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask import url_for, current_app

mail = Mail()

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=expiration)
    except Exception:
        return False
    return email

def send_confirmation_email(email, token):
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Please confirm your email"
    body = f"Click the link to confirm your email: {confirm_url}"
    msg = Message(subject, recipients=[email])
    msg.body = body
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
