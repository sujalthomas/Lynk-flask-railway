from flask import Flask, render_template
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail as FlaskMail
from flask_session import Session
from flask_bcrypt import Bcrypt
import os
import secrets
from dotenv import load_dotenv
import redis
from flask_cors import CORS
import logging 
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
import logging
from flask_limiter.util import get_remote_address
import openai


# Load environment variables
load_dotenv()

app = Flask(__name__)


bcrypt = Bcrypt(app)


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


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
