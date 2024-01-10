# FastAPI Server
from typing import Optional
import base64
import hmac
import hashlib
import json
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "077c6050eb086bc3c93e20b279e62a3a2677f59eb6346cdfec0d8e370e598ec2"
PASSWORD_SALT = "ac04a1f349d3537fb2ec3633d81f27a2e9043098db7fb54d806b16aaf9dea58f"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() )\
        .hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    'alexey@user.com': {
        'name': "Алексей",
        'password': "99e841298ce91d7cbadb65e5442d434e6ac80878f22625f3bcb127823184dfce",
        'balance': 100_000
    },
    'petr@user.com': {
        'name': "Петр",
        'password': "b2158e3472736b9472d3f6048e7b03b2cb79bcabd330b83c44ae41f797323087",
        'balance': 555_555
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r', encoding="utf-8") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланc: {users[valid_username]['balance']}", 
        media_type="text/html")


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    print('data is', data)
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        media_type="application/json")
    
    username_signed = base64.b64encode(username.encode()).decode() + '.' + \
    sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
