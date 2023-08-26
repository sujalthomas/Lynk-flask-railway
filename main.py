from flask import Flask, render_template
import os
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_session import Session



# Load environment variables
load_dotenv()

app = Flask(__name__)


bcrypt = Bcrypt(app)

#initialize extensions
sess = Session()
sess.init_app(app)




@app.route('/')
def index():
    return render_template('index.html')




if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
