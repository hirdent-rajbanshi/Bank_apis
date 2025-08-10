from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
import uuid

# App setup
app = Flask(__name__)

# JWT config
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory databases
users_db = {}  # key = username
accounts = {}  # key = user_id


# Utils
def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Unauthorized: No token provided or invalid format"}), 401
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in users_db:
            return jsonify({"detail": "Unauthorized: Invalid token or user"}), 401
        return users_db[username]
    except jwt.ExpiredSignatureError:
        return jsonify({"detail": "Unauthorized: Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"detail": "Unauthorized: Invalid token"}), 401


# 1. Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"detail": "Username and password are required"}), 400

    if username in users_db:
        return jsonify({"detail": "Username already exists"}), 400

    user_id = str(uuid.uuid4())
    users_db[username] = {
        "username": username,
        "hashed_password": get_password_hash(password),
        "id": user_id
    }
    accounts[user_id] = 0.0
    return jsonify({"message": "User created", "user_id": user_id})


# 2. Login (get token)
@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    username = data.get("username")
    password = data.get("password")

    user = users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return jsonify({"detail": "Invalid username or password"}), 401

    token = create_token({"sub": user["username"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return jsonify({"access_token": token, "token_type": "bearer"})


# 3. Deposit
@app.route("/deposit", methods=["POST"])
def deposit():
    current_user = get_current_user()
    if not isinstance(current_user, dict):
        return current_user  # returns the error JSON

    data = request.get_json()
    amount = data.get("amount")

    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"detail": "Amount must be a positive number"}), 400

    accounts[current_user["id"]] += amount
    return jsonify({"message": "Deposited", "balance": accounts[current_user["id"]]})


# 4. Withdraw
@app.route("/withdraw", methods=["POST"])
def withdraw():
    current_user = get_current_user()
    if not isinstance(current_user, dict):
        return current_user

    data = request.get_json()
    amount = data.get("amount")

    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"detail": "Amount must be a positive number"}), 400

    if amount > accounts[current_user["id"]]:
        return jsonify({"detail": "Insufficient balance"}), 400

    accounts[current_user["id"]] -= amount
    return jsonify({"message": "Withdrawn", "balance": accounts[current_user["id"]]})


# 5. Balance
@app.route("/balance", methods=["GET"])
def get_balance():
    current_user = get_current_user()
    if not isinstance(current_user, dict):
        return current_user
    return jsonify({"user_id": current_user["id"], "balance": accounts[current_user["id"]]})


if __name__ == "__main__":
    app.run(debug=True, port=8000)
