import morepath
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

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

def get_token_from_header(request):
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth[7:]
    return None


# ---------- Morepath App ----------
class App(morepath.App):
    pass


# Dummy models just to satisfy Morepath's routing
class Signup: pass
class Login: pass
class Deposit: pass
class Withdraw: pass
class Balance: pass


# ---------- Routes ----------
@App.path(model=Signup, path='signup')
def get_signup():
    return Signup()

@App.path(model=Login, path='login')
def get_login():
    return Login()

@App.path(model=Deposit, path='deposit')
def get_deposit():
    return Deposit()

@App.path(model=Withdraw, path='withdraw')
def get_withdraw():
    return Withdraw()

@App.path(model=Balance, path='balance')
def get_balance():
    return Balance()


# ---------- Views ----------
@App.json(model=Signup, request_method='POST')
def signup(self, request):
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        request.response.status = 400
        return {'message': 'Username and password required'}

    if username in users_db:
        request.response.status = 400
        return {'message': 'Username already exists'}

    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return {'message': 'User created', 'user_id': user_id}


@App.json(model=Login, request_method='POST')
def login(self, request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = users_db.get(username)

    if not user or not bcrypt.verify(password, user['hashed_password']):
        request.response.status = 401
        return {'message': 'Invalid username or password'}

    token = jwt.encode(
        {'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)},
        SECRET_KEY, algorithm='HS256'
    )
    return {'access_token': token, 'token_type': 'bearer'}


@App.json(model=Deposit, request_method='POST')
def deposit(self, request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        request.response.status = 401
        return {'message': err}

    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        request.response.status = 400
        return {'message': 'Amount must be positive'}

    accounts[user['id']] += amount
    return {'message': 'Deposited', 'balance': accounts[user['id']]}


@App.json(model=Withdraw, request_method='POST')
def withdraw(self, request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        request.response.status = 401
        return {'message': err}

    data = request.json
    amount = data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        request.response.status = 400
        return {'message': 'Amount must be positive'}

    if amount > accounts[user['id']]:
        request.response.status = 400
        return {'message': 'Insufficient balance'}

    accounts[user['id']] -= amount
    return {'message': 'Withdrawn', 'balance': accounts[user['id']]}


@App.json(model=Balance, request_method='GET')
def balance(self, request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        request.response.status = 401
        return {'message': err}
    return {'user_id': user['id'], 'balance': accounts[user['id']]}


# ---------- Run ----------
def main():
    morepath.commit(App)
    morepath.run(App(), host='localhost', port=8080)


if __name__ == '__main__':
    main()
