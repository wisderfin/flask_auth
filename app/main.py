from flask import Flask, render_template, request
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from app.config import Config
app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


@app.route('/registration')
def registration_render():
    return render_template('registration.html')


@app.route('/login')
def login_render():
    return render_template('login.html')

@app.route('/logout')
def logout_render():
    return render_template('logout.html')


from app.auth.views import router as auth
app.register_blueprint(auth)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

