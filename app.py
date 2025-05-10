
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
import pyotp
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['DEBUG'] = True

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'diplllom7@gmail.com'
app.config['MAIL_PASSWORD'] = 'bclowbvrifgftbpa'
mail = Mail(app)

def init_db():
    with sqlite3.connect('database.db') as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "email TEXT UNIQUE NOT NULL, "
            "password TEXT NOT NULL, "
            "otp_secret TEXT NOT NULL)"
        )

@app.route('/')
def index():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        try:
            with sqlite3.connect('database.db') as conn:
                conn.execute("INSERT INTO users (email, password, otp_secret) VALUES (?, ?, ?)",
                             (email, password, otp_secret))
            otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="2FA System")
            return render_template('qr.html', otp_uri=otp_uri)
        except sqlite3.IntegrityError:
            flash("Користувач з таким email вже існує")
            return redirect('/register')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('database.db') as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
            user = cur.fetchone()
        if user:
            session['email'] = email
            session['otp_secret'] = user[3]
            return redirect('/2fa')
        else:
            flash('Невірний email або пароль. <a href="/reset_request">Скинути пароль</a>')
            return redirect('/login')
    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'otp_secret' not in session:
        return redirect('/login')
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if not otp_input:
            flash("Код не введено")
            return redirect('/2fa')
        totp = pyotp.TOTP(session['otp_secret'])
        if totp.verify(otp_input):
            return redirect('/dashboard')
        else:
            flash("Невірний код")
            return redirect('/2fa')
    return render_template('two_factor.html')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html')
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        token = os.urandom(16).hex()
        reset_link = f"https://{request.host}/reset_password/{token}"
        session['reset_email'] = email
        session['reset_token'] = token
        msg = Message('Скидання пароля - 2FA Система',
                      sender='diplllom7@gmail.com',
                      recipients=[email])
        msg.body = f"Натисніть на посилання для скидання пароля: {reset_link}"
        mail.send(msg)
        flash("Лист для скидання пароля надіслано")
        return redirect('/login')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token != session.get('reset_token'):
        return "Невалідний токен", 400
    if request.method == 'POST':
        new_password = request.form['password']
        email = session.get('reset_email')
        with sqlite3.connect('database.db') as conn:
            conn.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
        flash("Пароль оновлено")
        return redirect('/login')
    return render_template('reset_password.html')

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
