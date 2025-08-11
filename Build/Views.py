from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
import jwt
from datetime import datetime, timedelta
import uuid
from passlib.hash import bcrypt

SECRET_KEY = 'your-secret-key'
accounts = {}

# ---------- Helper ----------
def create_jwt_token(username):
    return jwt.encode(
        {'sub': username, 'exp': datetime.utcnow() + timedelta(minutes=30)},
        SECRET_KEY,
        algorithm='HS256'
    )

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload.get('sub')
        if not User.objects.filter(username=username).exists():
            return None, 'Invalid token or user'
        return User.objects.get(username=username), None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except Exception:
        return None, 'Invalid token'


# ---------- API Endpoints ----------
@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'message': 'Username and password required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'message': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, password=password)
    user_id = str(uuid.uuid4())
    accounts[user_id] = 0.0
    user.profile_id = user_id
    user.save()

    return Response({'message': 'User created', 'user_id': user_id})


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(username=username, password=password)
    if not user:
        return Response({'message': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

    token = create_jwt_token(username)
    return Response({'access_token': token, 'token_type': 'bearer'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deposit(request):
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]
    else:
        return Response({'message': 'Token required'}, status=status.HTTP_401_UNAUTHORIZED)

    user, err = verify_jwt_token(token)
    if err:
        return Response({'message': err}, status=status.HTTP_401_UNAUTHORIZED)

    amount = request.data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return Response({'message': 'Amount must be positive'}, status=status.HTTP_400_BAD_REQUEST)

    accounts[user.profile_id] += amount
    return Response({'message': 'Deposited', 'balance': accounts[user.profile_id]})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def withdraw(request):
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]
    else:
        return Response({'message': 'Token required'}, status=status.HTTP_401_UNAUTHORIZED)

    user, err = verify_jwt_token(token)
    if err:
        return Response({'message': err}, status=status.HTTP_401_UNAUTHORIZED)

    amount = request.data.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return Response({'message': 'Amount must be positive'}, status=status.HTTP_400_BAD_REQUEST)

    if amount > accounts[user.profile_id]:
        return Response({'message': 'Insufficient balance'}, status=status.HTTP_400_BAD_REQUEST)

    accounts[user.profile_id] -= amount
    return Response({'message': 'Withdrawn', 'balance': accounts[user.profile_id]})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def balance(request):
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token[7:]
    else:
        return Response({'message': 'Token required'}, status=status.HTTP_401_UNAUTHORIZED)

    user, err = verify_jwt_token(token)
    if err:
        return Response({'message': err}, status=status.HTTP_401_UNAUTHORIZED)

    return Response({'user_id': user.profile_id, 'balance': accounts[user.profile_id]})
