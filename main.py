from flask import Flask, render_template
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail as FlaskMail
from flask_session import Session
from flask_bcrypt import Bcrypt
import os , random , secrets
from dotenv import load_dotenv
import redis
from flask_cors import CORS
import logging 
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
import logging
from flask_limiter.util import get_remote_address
import openai
from datetime import datetime, timedelta
from flask_security_too import (
    Security,
    SQLAlchemyUserDatastore,
    UserMixin,
    RoleMixin,
    roles_required,
    login_required,
)
from werkzeug.security import generate_password_hash as encrypt_password
from wtforms import StringField
from wtforms.validators import DataRequired
from flask_security_too.forms import RegisterForm
from flask_mail import Message




# Load environment variables
load_dotenv()

app = Flask(__name__)


bcrypt = Bcrypt(app)


import subprocess

def install_package(package_name):
    try:
        subprocess.check_call(["pip", "install", package_name])
        print(f"Successfully installed {package_name}")
    except subprocess.CalledProcessError as e:
        print(f"Error installing {package_name}: {e}")

# Example usage:
install_package("Flask-Security-Too")




# Secuirty configurations
SECRET_KEY = os.getenv("SECRET_KEY", default=secrets.token_urlsafe(16))
app.config["SECRET_KEY"] = SECRET_KEY
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

app.config["SECURITY_PASSWORD_SALT"] = os.getenv(
    "SECURITY_PASSWORD_SALT", default="your_random_salt"
)
app.config["SECURITY_REGISTERABLE"] = True
app.config["SECURITY_RECOVERABLE"] = True
app.config["SECURITY_PASSWORD_SALT"] = os.getenv(
    "SECURITY_PASSWORD_SALT", default="your_random_salt"
)

# Database configurations
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Database configuration
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)



CORS(
    app,
    resources={r"/*": {"origins": ["https://www.linkedin.com"]}},
    supports_credentials=True,
)

# Mail Configurations
app.config["MAIL_SERVER"] = "smtp.sendgrid.net"
app.config["MAIL_PORT"] = 587  # 465 for TLS
app.config["MAIL_USERNAME"] = "apikey"
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
mail = FlaskMail(app)




# Generate DB tables
with app.app_context():
    db.create_all()

# MODELS ###############
# Define models #######

#cvs generated
class CoverLetter(db.Model):
    cover_letter_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    company_name = db.Column(db.String(100))
    job_listing = db.Column(db.Text)
    recruiter = db.Column(db.String(100))
    date = db.Column(db.DateTime, default=db.func.CURRENT_TIMESTAMP)
    file_path = db.Column(db.String(255))
    user = db.relationship("User", backref="cover_letters")

# resumes uploaded
class Resume(db.Model):
    resume_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    content = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="resumes")

# usage statistics
class UsageStatistic(db.Model):
    stat_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    action = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=db.func.CURRENT_TIMESTAMP)
    user = db.relationship("User", backref="usage_statistics")

# Define roles
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

# user roles
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.user_id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)

class User(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    fs_uniquifier = db.Column(db.String(255), unique=True)
    roles = db.relationship(
        "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
    )
    
    # New columns for reset code and its expiration
    password_reset_code = db.Column(db.String(6))
    password_reset_code_expiration = db.Column(db.DateTime)
    
    # New columns for email verification
    is_active = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    verification_code_expiration = db.Column(db.DateTime)


#proceeding to remove db stuff and establish flask security



# Define hashed_password
password = "supersecretpassword"
hashed_password = encrypt_password(password)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)


# Custom registration form
class ExtendedRegisterForm(RegisterForm):
    username = StringField("Username", [DataRequired()])





# Routes ###############
# Define routes #######
# api key verification


@app.route('/')
def index():
    return render_template('index.html')

# Utils ###############
# Define utils #######

def is_api_key_valid(api_key):
    openai.api_key = api_key
    try:
        response = openai.Completion.create(
            engine="davinci", prompt="This is a test.", max_tokens=5
        )
    except:
        return False
    else:
        return True
    

@app.route("/apiverify", methods=["POST"])
def apiverify():
    data = request.get_json()
    api_key = data.get("apiKey")

    try:
        if is_api_key_valid(api_key):
            token = serializer.dumps({"user": "YOUR_USER_IDENTIFIER"})
            return jsonify(success=True, token=token)
        else:
            raise Exception("Invalid API key")
    except Exception as e:
        logging.error(str(e))
        return jsonify(success=False, message="Invalid API key"), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify(success=False, message="User already exists"), 400

    user_role = Role.query.filter_by(name="user").first()
    if not user_role:
        user_role = Role(name="user", description="Regular user")
        db.session.add(user_role)
        db.session.commit()

    new_user = User(email=email, password=hashed_password, is_active=False)
    new_user.roles.append(user_role)
    db.session.add(new_user)
    db.session.commit()

    # Generate verification code
    code = str(random.randint(100000, 999999))
    new_user.verification_code = code
    new_user.verification_code_expiration = datetime.utcnow() + timedelta(minutes=30)
    db.session.commit()

    # Send verification code to user's email
    msg = Message("Verification Code", sender="lynktools@gmail.com", recipients=[email])
    msg.body = f"Your verification code is: {code}"
    try:
        mail.send(msg)
    except Exception as e:
        logging.error(f"Error sending email to {email}: {str(e)}")
        return jsonify(success=False, message="Error sending email."), 500

    return jsonify(success=True, message="Verification code has been sent to your email."), 200

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(success=False, message="User not found"), 404

    if user.verification_code != code or datetime.utcnow() > user.verification_code_expiration:
        return jsonify(success=False, message="Invalid or expired code"), 401

    user.is_active = True
    user.verification_code = None
    user.verification_code_expiration = None
    db.session.commit()

    return jsonify(success=True, message="Registration successful"), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password) or not user.is_active:
        return jsonify(success=False, message="Invalid email or password"), 401

    token = serializer.dumps({"user": user.user_id}, salt="password-reset")
    return jsonify(success=True, token=token), 200






# admin page
@app.route("/admin")
@roles_required("admin")
@login_required
def admin():
    return "Admin Page"



if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
