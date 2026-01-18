from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
from typing import Annotated
import json
from pydantic import BaseModel
from pwdlib import PasswordHash
from starlette.status import HTTP_303_SEE_OTHER
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi.templating import Jinja2Templates

app = FastAPI()

SECRET_KEY = "NzlMoUceQgB61oj9VnqrNMNpCcWXuto+cjU="
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

templates = Jinja2Templates(directory="templates")

password_hash = PasswordHash.recommended()

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

class TokenData(BaseModel):
    username: str | None = None

file_name = 'fake_db.json'
try:
    with open(file_name, 'r') as file:
        fake_db = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    fake_db = {}

def get_password_hash(password):
    return password_hash.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def authenticate_user(fake_db, password: str, username: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    user_verified = verify_password(password, user.hashed_password)
    if not user_verified:
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not autherised to enter this page"
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except Exception:
        return RedirectResponse(url="/signin", status_code=HTTP_303_SEE_OTHER)

@app.post('/token')
async def login_for_access_token(response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()],):
    user = authenticate_user(fake_db, form_data.password, form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    response = RedirectResponse(url="/dashboard", status_code=HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800
    )
    return response
    
@app.get('/signup')
async def get_sign_up_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post('/signup')
async def sign_up_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    if form_data.username in fake_db:
        return RedirectResponse(url="/signin", status_code=HTTP_303_SEE_OTHER)
    hashed_password = get_password_hash(form_data.password)
    fake_db[form_data.username] = {
        "username": form_data.username,
        "hashed_password": hashed_password,
    }
    with open (file_name, 'w') as file_json:
        json.dump(fake_db, file_json, indent=4)
    return RedirectResponse(url='/signin', status_code=HTTP_303_SEE_OTHER)

@app.get("/signin")
async def sign_in_user(request: Request):
    return templates.TemplateResponse("signin.html", {"request": request})

@app.get("/dashboard")
async def get_dashboard(request: Request, username: Annotated[str, Depends(verify_token)]):    
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": username})
        
