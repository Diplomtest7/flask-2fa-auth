from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
from PIL import Image
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@app.route("/")
def index():
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp_secret = pyotp.random_base32()
        user = User(email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('two_factor'))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = email
            return redirect(url_for('two_factor'))
        flash("Невірний email або пароль")
    return render_template("login.html")

def generate_qr_code(uri):
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode()
    return img_base64

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if request.method == "POST":
        otp_input = request.form.get('otp')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_input):
            return "Успішна автентифікація"
        flash("Невірний код")
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=email, issuer_name="2FA Auth")
    qr_code_img = generate_qr_code(otp_uri)
    return render_template("two_factor.html", qr_code=qr_code_img)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
