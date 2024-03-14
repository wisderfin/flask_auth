from flask import jsonify, Blueprint, request, make_response
from flask.views import MethodView
from app.auth.models import User, BlacklistToken
from app.main import db, bcrypt

router = Blueprint('auth', __name__)


class RegistrationAPI(MethodView):
    @staticmethod
    def post():
        user = User.query.filter_by(login=request.form['login']).first()
        if not user:
            user = User(
                login=request.form['login'],
                email=request.form['email'],
                password=request.form['password']
            )
            db.session.add(user)
            db.session.commit()

            auth_token = user.encode_auth_token(user.id)
            responseObject = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token
            }
            return make_response(jsonify(responseObject)), 201
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please log in.'
        }
        return make_response(jsonify(responseObject)), 409


class LoginAPI(MethodView):
    @staticmethod
    def post():
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token
                }
                return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return make_response(jsonify(responseObject)), 404


class UserAPI(MethodView):
    @staticmethod
    def get():
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(' ')[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response, str):
                user = User.query.filter_by(id=response).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': response
            }
            return make_response(jsonify(responseObject)), 401
        responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
        return make_response(jsonify(responseObject)), 401


class LogoutAPI(MethodView):
    @staticmethod
    def post():
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            response = User.decode_auth_token(auth_token)
            if not isinstance(response, str):
                blacklist_token = BlacklistToken(token=auth_token)
                db.session.add(blacklist_token)
                db.session.commit()
                responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                    'status': 'fail',
                    'message': response
                }
            return make_response(jsonify(responseObject)), 401
        responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
        return make_response(jsonify(responseObject)), 401


registration_view = RegistrationAPI.as_view('registration_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

router.add_url_rule(
    '/auth/registration',
    view_func=registration_view,
    methods=['POST']
)
router.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
router.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
router.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
