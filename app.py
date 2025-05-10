from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 8025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'

mail = Mail(app)
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.secret_key)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=True)

def generate_qr_code(otp_uri):
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return img_base64

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email вже зареєстровано.', 'danger')
            return redirect(url_for('register'))

        otp_secret = pyotp.random_base32()
        new_user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    user_id = session.get('user_id')
    if not user_id:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    totp = pyotp.TOTP(user.otp_secret)
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if otp_input and totp.verify(otp_input):
            flash('Двофакторна аутентифікація успішна!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Код не вірний або не введено.', 'danger')
            return render_template('two_factor.html')
    otp_uri = totp.provisioning_uri(name=user.email, issuer_name="2FA Flask App")
    qr_code_img = generate_qr_code(otp_uri)
    return render_template('two_factor.html', qr_code=qr_code_img)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('two_factor'))
        flash('Невірний email або пароль.', 'danger')
    return render_template('login.html')

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            link = url_for('reset_token', token=token, _external=True)
            # Тут має бути реальна відправка листа
            print(f"Reset link: {link}")
            flash('Лист для скидання пароля надіслано (імітація)', 'info')
            return redirect(url_for('login'))
        flash('Користувача не знайдено.', 'danger')
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('Неправильний або протермінований токен.', 'danger')
        return redirect(url_for('reset_request'))

    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        password = request.form['password']
        user.password = password
        db.session.commit()
        session['user_id'] = user.id
        return redirect(url_for('two_factor'))

    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
