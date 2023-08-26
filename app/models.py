from datetime import datetime
from . import db
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
    UserMixin,
    RoleMixin,
    roles_required,
    login_required,
)
from werkzeug.security import generate_password_hash as encrypt_password
from werkzeug.security import check_password_hash as verify_password
from flask_security.forms import RegisterForm, LoginForm
from wtforms import StringField
from wtforms.validators import DataRequired


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