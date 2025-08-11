from bottle import Bottle, request, response, run
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

app = Bottle()

SECRET_KEY = 'your-secret-key'
users_db = {}
accounts = {}

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

def get_token_from_header():
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None

@app.post('/signup')
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        response.status = 400
        return {'message': 'Username and password required'}
    if username in users_db:
        response.status = 400
        return {'message': 'Username already exists'}
    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return {'message': 'User created', 'user_id': user_id}

@app.post('/login')
def login():
    data = request.forms
    username = data.get('username')
    password = data.get('password')
    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        response.status = 401
        return {'message': 'Invalid username or password'}
    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer'}

@app.post('/deposit')
def deposit():
    token = get_token_from_header()
    user, err = verify_token(token)
    if err:
        response.status = 401
        return {'message': err}
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        response.status = 400
        return {'message': 'Amount must be positive'}
    accounts[user['id']] += amount
    return {'message': 'Deposited', 'balance': accounts[user['id']]}

@app.post('/withdraw')
def withdraw():
    token = get_token_from_header()
    user, err = verify_token(token)
    if err:
        response.status = 401
        return {'message': err}
    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        response.status = 400
        return {'message': 'Amount must be positive'}
    if amount > accounts[user['id']]:
        response.status = 400
        return {'message': 'Insufficient balance'}
    accounts[user['id']] -= amount
    return {'message': 'Withdrawn', 'balance': accounts[user['id']]}

@app.get('/balance')
def balance():
    token = get_token_from_header()
    user, err = verify_token(token)
    if err:
        response.status = 401
        return {'message': err}
    return {'user_id': user['id'], 'balance': accounts[user['id']]}

if __name__ == '__main__':
    run(app, host='localhost', port=8080, debug=True)