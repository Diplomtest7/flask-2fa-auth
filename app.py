from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, sqlite3
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config.from_pyfile('config.py')
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY,
                 email TEXT UNIQUE,
                 password TEXT,
                 otp_secret TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp_secret = pyotp.random_base32()
        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (email, password, otp_secret) VALUES (?, ?, ?)", (email, password, otp_secret))
                conn.commit()
            session['email'] = email
            return redirect(url_for('two_factor_setup'))
        except:
            flash("Користувач з таким email вже існує.")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE email=?", (email,))
            row = c.fetchone()
        if row and check_password_hash(row[0], password):
            session['email'] = email
            return redirect(url_for('two_factor'))
        else:
            flash("Невірний email або пароль. <a href='/reset_request'>Скинути пароль</a>")
    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT otp_secret FROM users WHERE email=?", (email,))
            otp_secret = c.fetchone()[0]
        totp = pyotp.TOTP(otp_secret)
        if totp.verify(code):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            flash("Невірний код. Спробуйте ще раз.")
    return render_template('two_factor.html')

@app.route('/2fa/setup')
def two_factor_setup():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE email=?", (email,))
        otp_secret = c.fetchone()[0]
    totp = pyotp.TOTP(otp_secret)
    otp_uri = totp.provisioning_uri(name=email, issuer_name="2FA Demo")
    return render_template('qr.html', otp_uri=otp_uri)

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        token = s.dumps(email, salt='reset-password')
        link = url_for('reset_token', token=token, _external=True)
        msg = Message('Скидання пароля', sender='diplllom7@gmail.com', recipients=[email])
        msg.body = f'Перейдіть за посиланням для скидання пароля: {link}'
        mail.send(msg)
        flash("Інструкція для скидання пароля надіслана на email.")
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=3600)
    except:
        flash("Недійсний або прострочений токен.")
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        new_password = generate_password_hash(request.form['password'])
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
            conn.commit()
        flash("Пароль успішно змінено.")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.secret_key = app.config['SECRET_KEY']
    app.run(debug=True)
