from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import pyotp
import os
import qrcode
import io
import base64

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

# ========== ROUTES ==========

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    return render_template('reset_request.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/qr')
def qr():
    return render_template('qr.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('register'))
    user = User.query.filter_by(email=email).first()
    otp_uri = f"otpauth://totp/Flask2FA:{email}?secret={user.otp_secret}&issuer=Flask2FA"
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('two_factor.html', qr_code=qr_code)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
