import os
import base64
import io
import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Налаштування для надсилання email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'diplllom7@gmail.com'
app.config['MAIL_PASSWORD'] = 'bclowbvrifgftbpa'
mail = Mail(app)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False)

with app.app_context():
    db.create_all()

def generate_qr_code(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp_secret = pyotp.random_base32()
        if User.query.filter_by(email=email).first():
            flash('Email вже зареєстрований.')
            return redirect(url_for('register'))
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = email
            return redirect(url_for('two_factor'))
        flash('Невірні дані для входу.')
    return render_template('login.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    otp_uri = f"otpauth://totp/Flask2FA:{user.email}?secret={user.otp_secret}&issuer=Flask2FA"
    qr_code = generate_qr_code(otp_uri)
    if request.method == 'POST':
        code = request.form['otp_code']
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(code):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        flash('Невірний код. Спробуйте ще.')
    return render_template('two_factor.html', qr_code=qr_code)

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == "POST":
        if 'email' in request.form:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            if user:
                reset_code = str(random.randint(100000, 999999))
                session['reset_email'] = email
                session['reset_code'] = reset_code

                msg = Message('Код для скидання пароля',
                              sender='your_email@example.com',
                              recipients=[email])
                msg.body = f'Ваш код для скидання пароля: {reset_code}'
                mail.send(msg)

                flash('Код надіслано на пошту.')
                return render_template('reset_request.html', show_code_field=True)

            else:
                flash('Користувача з такою поштою не знайдено.')
        elif 'reset_code' in request.form:
            entered_code = request.form['reset_code']
            if entered_code == session.get('reset_code'):
                flash('Код підтверджено! Тепер ви можете задати новий пароль.')
                return redirect(url_for('reset_password'))
            else:
                flash('Невірний код. Спробуйте ще раз.')
                return render_template('reset_request.html', show_code_field=True)

    return render_template('reset_request.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
