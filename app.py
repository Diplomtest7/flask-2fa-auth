import io
import qrcode
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_password'

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        otp_secret = pyotp.random_base32()
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template('register.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'email' not in session:
        return redirect(url_for('register'))

    user = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if pyotp.TOTP(user.otp_secret).verify(otp_input):
            flash('Two-factor authentication successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('two_factor'))

    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.email, issuer_name='Flask2FAApp')
    qr_code_img = generate_qr_code(otp_uri)
    return render_template('two_factor.html', qr_code_img=qr_code_img)

@app.route('/dashboard')
def dashboard():
    return 'Welcome to your dashboard!'

def generate_qr_code(otp_uri):
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_img = buf.getvalue()
    encoded_img = "data:image/png;base64," + base64.b64encode(qr_code_img).decode('utf-8')
    return encoded_img

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
