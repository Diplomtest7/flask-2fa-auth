import os
import qrcode
import io
import base64
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
            flash('Email already зареєстрований.')
            return redirect(url_for('register'))
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('register'))
    user = User.query.filter_by(email=email).first()
    otp_uri = f'otpauth://totp/Flask2FA:{email}?secret={user.otp_secret}&issuer=Flask2FA'
    qr_code = generate_qr_code(otp_uri)
    send_verification_email(email, user.otp_secret[:6])
    return render_template('two_factor.html', qr_code=qr_code)

@app.route('/qr')
def qr_page():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    otp_uri = f'otpauth://totp/Flask2FA:{email}?secret={user.otp_secret}&issuer=Flask2FA'
    qr_code = generate_qr_code(otp_uri)
    return render_template('qr.html', qr_code=qr_code)

@app.route('/dashboard')
def dashboard():
    email = session.get('email')
    if not email:
        flash('Будь ласка, увійдіть спочатку.')
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=email)

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    return render_template('reset_request.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Ви вийшли з акаунту.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)