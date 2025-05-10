from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(16))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        otp_secret = pyotp.random_base32()
        new_user = User(email=email, password=hashed_pw, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        return redirect(url_for('show_qr'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('two_factor'))
        flash('Невірний email або пароль.', 'danger')
    return render_template('login.html')

@app.route('/show_qr')
def show_qr():
    user = db.session.get(User, session['user_id'])
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.email, issuer_name='2FA App')
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('show_qr.html', img_data=img_base64)

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = request.form.get('otp', '').replace(' ', '')
        if not otp_input:
            flash('Код не введено', 'warning')
            return redirect(url_for('two_factor'))

        user = db.session.get(User, session['user_id'])
        if user and user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp_input):
                session['authenticated'] = True
                flash('Вхід успішний', 'success')
                return redirect(url_for('success'))
            else:
                flash('Неправильний код', 'danger')
        else:
            flash('Двофакторна аутентифікація не налаштована', 'danger')

    return render_template('two_factor.html')

@app.route('/success')
def success():
    if session.get('authenticated'):
        return "Ви успішно увійшли!"
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
