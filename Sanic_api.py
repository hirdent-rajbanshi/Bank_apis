from sanic import Sanic, response
from sanic.request import Request
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

app = Sanic("BankingAPI")

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


# ---------- Routes ----------
@app.post("/signup")
async def signup(request: Request):
    try:
        data = request.json
    except:
        return response.json({'message': 'Invalid JSON'}, status=400)

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return response.json({'message': 'Username and password required'}, status=400)

    if username in users_db:
        return response.json({'message': 'Username already exists'}, status=400)

    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hash(password)
    users_db[username] = {'username': username, 'hashed_password': hashed_password, 'id': user_id}
    accounts[user_id] = 0.0
    return response.json({'message': 'User created', 'user_id': user_id})


@app.post("/login")
async def login(request: Request):
    data = request.form or {}
    username = data.get('username')
    password = data.get('password')

    user = users_db.get(username)
    if not user or not bcrypt.verify(password, user['hashed_password']):
        return response.json({'message': 'Invalid username or password'}, status=401)

    token = jwt.encode({'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')
    return response.json({'access_token': token, 'token_type': 'bearer'})


@app.post("/deposit")
async def deposit(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return response.json({'message': err}, status=401)

    data = request.json
    amount = data.get('amount')

    if not isinstance(amount, (int, float)) or amount <= 0:
        return response.json({'message': 'Amount must be positive'}, status=400)

    accounts[user['id']] += amount
    return response.json({'message': 'Deposited', 'balance': accounts[user['id']]})


@app.post("/withdraw")
async def withdraw(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return response.json({'message': err}, status=401)

    data = request.json
    amount = data.get('amount')

    if not isinstance(amount, (int, float)) or amount <= 0:
        return response.json({'message': 'Amount must be positive'}, status=400)

    if amount > accounts[user['id']]:
        return response.json({'message': 'Insufficient balance'}, status=400)

    accounts[user['id']] -= amount
    return response.json({'message': 'Withdrawn', 'balance': accounts[user['id']]})


@app.get("/balance")
async def balance(request: Request):
    token = get_token_from_header(request)
    user, err = verify_token(token)
    if err:
        return response.json({'message': err}, status=401)
    return response.json({'user_id': user['id'], 'balance': accounts[user['id']]})


# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)
