from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'diplllom7@gmail.com'
app.config['MAIL_PASSWORD'] = 'bclowbvrifgftbpa'  # Використовуй App Password
app.config['MAIL_DEFAULT_SENDER'] = 'diplllom7@gmail.com'

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp_secret = pyotp.random_base32()
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        flash("Не знайдено email у сесії")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if not otp_input:
            flash("Код не введено")
            return render_template('two_factor.html')
        
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_input):
            flash("Аутентифікація пройдена")
            return redirect(url_for('dashboard'))
        else:
            flash("Невірний код")
    return render_template('two_factor.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = email
            return redirect(url_for('two_factor'))
        else:
            flash('Невірний email або пароль. <a href="/reset_request">Скинути пароль</a>', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = base64.b64encode(email.encode()).decode()
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Скидання пароля', recipients=[email])
            msg.body = f'Щоб скинути пароль, перейдіть за цим посиланням: {reset_link}'
            try:
                mail.send(msg)
                flash('Лист для скидання пароля надіслано (імітація)', 'info')
            except Exception as e:
                flash('Помилка надсилання листа: ' + str(e), 'danger')
        else:
            flash('Користувача з такою поштою не знайдено.', 'danger')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = base64.b64decode(token.encode()).decode()
    except:
        flash("Недійсний токен", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Користувача не знайдено", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
