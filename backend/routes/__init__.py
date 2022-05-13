import jwt
from flask_httpauth import HTTPTokenAuth, HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


allowed_users = {
    "jack": generate_password_hash("my-pass"),
    "sully": generate_password_hash("your-pass")
}

allowed_tokens = {
    "token-jack": "jack",
    "token-sully": "sully"
}


basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth(scheme="Bearer")


@basic_auth.verify_password
def verify_basic_password(username, password):
    if username not in allowed_users:
        return None

    if check_password_hash(allowed_users[username], password):
        return username


@token_auth.verify_token
def verify_token(token):
    try:
        decoded_jwt = jwt.decode(token, "mysecret", algorithm=["HS256"])
    except Exception as e:
        return None

    if decoded_jwt["name"] in allowed_users:
        return decoded_jwt["name"]

    return None

