
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import pyotp
import qrcode
import io
from PIL import Image
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_password'

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        otp_secret = pyotp.random_base32()
        new_user = User(email=email, password=hashed_password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Користувача не знайдено.")
        return redirect(url_for('login'))
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=email, issuer_name="2FA App")
    qr_code_img = generate_qr_code(otp_uri)
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if pyotp.TOTP(user.otp_secret).verify(otp_input):
            flash("Двофакторна автентифікація пройдена.")
            return redirect(url_for('login'))
        else:
            flash("Невірний код.")
    return render_template('two_factor.html', qr_code=qr_code_img)

def generate_qr_code(otp_uri):
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_bytes = buf.getvalue()
    base64_img = base64.b64encode(img_bytes).decode('utf-8')
    return base64_img

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
