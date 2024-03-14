from datetime import datetime, timezone, timedelta
from app.main import db, bcrypt
import jwt
from settings import settings


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __init__(self, login, email, password):
        self.login = login
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, settings.BCRYPT_LOG_ROUNDS
        ).decode()

    @staticmethod
    def encode_auth_token(user_id):
        payload = {
            'exp': datetime.now(timezone.utc) + timedelta(days=7),
            'iat': datetime.now(timezone.utc),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            settings.KEY,
            algorithm='HS256'
        )

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(
                auth_token,
                settings.KEY
            )
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class BlacklistToken(db.Model):
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String, unique=True, nullable=False)

    def __init__(self, token):
        self.token = token

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        return False


