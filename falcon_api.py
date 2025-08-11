import falcon
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt
import json

SECRET_KEY = 'your-secret-key'

users_db = {}
accounts = {}

def get_token_from_header(req):
    auth = req.get_header('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

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

class Signup:
    def on_post(self, req, resp):
        data = json.load(req.bounded_stream)
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            resp.status = falcon.HTTP_400
            resp.media = {'message': 'Username and password required'}
            return
        if username in users_db:
            resp.status = falcon.HTTP_400
            resp.media = {'message': 'Username already exists'}
            return
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hash(password)
        users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
        accounts[user_id] = 0.0
        resp.media = {'message': 'User created', 'user_id': user_id}

class Login:
    def on_post(self, req, resp):
        data = req.get_media()
        username = data.get('username')
        password = data.get('password')
        user = users_db.get(username)
        if not user or not bcrypt.verify(password, user['hashed_password']):
            resp.status = falcon.HTTP_401
            resp.media = {'message': 'Invalid username or password'}
            return
        token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
        resp.media = {'access_token': token, 'token_type': 'bearer'}

class Deposit:
    def on_post(self, req, resp):
        token = get_token_from_header(req)
        user, err = verify_token(token)
        if err:
            resp.status = falcon.HTTP_401
            resp.media = {'message': err}
            return
        data = req.get_media()
        amount = data.get('amount')
        if not isinstance(amount, (int, float)) or amount <= 0:
            resp.status = falcon.HTTP_400
            resp.media = {'message': 'Amount must be positive'}
            return
        accounts[user['id']] += amount
        resp.media = {'message': 'Deposited', 'balance': accounts[user['id']]}

class Withdraw:
    def on_post(self, req, resp):
        token = get_token_from_header(req)
        user, err = verify_token(token)
        if err:
            resp.status = falcon.HTTP_401
            resp.media = {'message': err}
            return
        data = req.get_media()
        amount = data.get('amount')
        if not isinstance(amount, (int, float)) or amount <= 0:
            resp.status = falcon.HTTP_400
            resp.media = {'message': 'Amount must be positive'}
            return
        if amount > accounts[user['id']]:
            resp.status = falcon.HTTP_400
            resp.media = {'message': 'Insufficient balance'}
            return
        accounts[user['id']] -= amount
        resp.media = {'message': 'Withdrawn', 'balance': accounts[user['id']]}

class Balance:
    def on_get(self, req, resp):
        token = get_token_from_header(req)
        user, err = verify_token(token)
        if err:
            resp.status = falcon.HTTP_401
            resp.media = {'message': err}
            return
        resp.media = {'user_id': user['id'], 'balance': accounts[user['id']]}

app = falcon.App()
app.add_route('/signup', Signup())
app.add_route('/login', Login())
app.add_route('/deposit', Deposit())
app.add_route('/withdraw', Withdraw())
app.add_route('/balance', Balance())