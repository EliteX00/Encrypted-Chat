from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import jwt
import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = '69c805d6b1a609f2b9c2db1a3a08102a38131f70a4d7e119308e071a89504664'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'horizonmailer555@gmail.com'
app.config['MAIL_PASSWORD'] = ''

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)

def generate_token(email):
    payload = {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(email=data['email'], password=hashed_password)
    db.session.add(user)
    db.session.commit()
    token = generate_token(user.email)
    verification_link = f"http://localhost:5000/verify/{token}"
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Click the link to verify your email: {verification_link}'
    mail.send(msg)
    return jsonify({'message': 'User registered, check email for verification.'})

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(email=data['email']).first()
        if user:
            user.verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully.'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Verification link expired.'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        if not user.verified:
            return jsonify({'message': 'Email not verified.'}), 403
        session['user'] = user.email
        return jsonify({'message': 'Login successful'})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logged out successfully'})

if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()
    app.run(debug=True)

