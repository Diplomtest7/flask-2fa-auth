from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import pyotp
import qrcode
from io import BytesIO
import base64
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your@example.com'
app.config['MAIL_PASSWORD'] = 'password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        new_user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        session['otp_secret'] = otp_secret
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    otp_secret = session.get('otp_secret')
    if not otp_secret:
        flash("Код не знайдено")
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        totp = pyotp.TOTP(otp_secret)
        if totp.verify(otp_input):
            session['user_id'] = otp_secret
            return redirect(url_for('dashboard'))
        else:
            flash('Невірний код. Спробуйте ще раз.')
            return redirect(url_for('two_factor'))

    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name="2FA System", issuer_name="MyApp")
    qr_code_img = generate_qr_code(otp_uri)
    return render_template('two_factor.html', qr_code_img=qr_code_img)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return "Вітаємо в системі з 2FA!"

def generate_qr_code(otp_uri):
    img = qrcode.make(otp_uri)
    buf = BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return qr_b64

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)