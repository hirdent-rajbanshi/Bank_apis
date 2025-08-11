from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.request import Request
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt
import json

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

# ---------- Helper Functions ----------
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload.get('sub')
        if not username or username not in users_db:
            return None, 'Invalid token or user'
        return users_db[username], None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except Exception:
        return None, 'Invalid token'

def get_token_from_header(request: Request):
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

def json_response(data, status=200):
    return Response(
        body=json.dumps(data),
        content_type="application/json",
        status=status
    )

# ---------- Routes ----------
@view_config(route_name='signup', request_method='POST')
def signup(request: Request):
    try:
        data = request.json_body
    except:
        return json_response({'message': 'Invalid JSON'}, 400)

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return json_response({'message': 'Username and password required'}, 400)

    if username in users_db:
        return json_response({'message': 'Username already exists'}, 400)

    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return json_response({'message': 'User created', 'user_id': user_id})


@view_config(route_name='login', request_method='POST')
def login(request: Request):
    data = request.POST or {}
    username = data.get('username')
    password = data.get('password')

    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        return json_response({'message': 'Invalid username or password'}, 401)

    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return json_response({'access_token': token, 'token_type': 'bearer'})


@view_config(route_name='deposit', request_method='POST')
def deposit(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json_response({'message': err}, 401)

    try:
        data = request.json_body
    except:
        return json_response({'message': 'Invalid JSON'}, 400)

    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return json_response({'message': 'Amount must be positive'}, 400)

    accounts[user['id']] += amount
    return json_response({'message': 'Deposited', 'balance': accounts[user['id']]})


@view_config(route_name='withdraw', request_method='POST')
def withdraw(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json_response({'message': err}, 401)

    try:
        data = request.json_body
    except:
        return json_response({'message': 'Invalid JSON'}, 400)

    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return json_response({'message': 'Amount must be positive'}, 400)

    if amount > accounts[user['id']]:
        return json_response({'message': 'Insufficient balance'}, 400)

    accounts[user['id']] -= amount
    return json_response({'message': 'Withdrawn', 'balance': accounts[user['id']]})


@view_config(route_name='balance', request_method='GET')
def balance(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return json_response({'message': err}, 401)

    return json_response({'user_id': user['id'], 'balance': accounts[user['id']]})


# ---------- Run ----------
if __name__ == '__main__':
    with Configurator() as config:
        config.add_route('signup', '/signup')
        config.add_route('login', '/login')
        config.add_route('deposit', '/deposit')
        config.add_route('withdraw', '/withdraw')
        config.add_route('balance', '/balance')
        config.scan()
        app = config.make_wsgi_app()

    server = make_server('0.0.0.0', 8080, app)
    print("🚀 Pyramid API running at http://localhost:8080")
    server.serve_forever()
