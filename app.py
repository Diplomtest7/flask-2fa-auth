import os
import qrcode
import io
import base64
import pyotp
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False)

with app.app_context():
    db.create_all()

def send_verification_email(email, otp_code):
    msg = Message('Your 2FA Code', recipients=[email], sender=app.config['MAIL_USERNAME'])
    msg.body = f'Your verification code is: {otp_code}'
    mail.send(msg)

def generate_qr_code(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return qr_code_b64

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        flash('Session expired or user not found.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.")
        return redirect(url_for('register'))
    otp_uri = f'otpauth://totp/Flask2FA:{email}?secret={user.otp_secret}&issuer=Flask2FA'
    qr_code = generate_qr_code(otp_uri)
    if request.method == 'POST':
        input_code = request.form.get('otp')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(input_code):
            flash('2FA verification successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid code. Please try again.')
    return render_template('two_factor.html', qr_code=qr_code)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
