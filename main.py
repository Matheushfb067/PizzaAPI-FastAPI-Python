from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext # Ferramenta para criar a criptografica das nossas senhas
from dotenv import load_dotenv # Carrega as variaveis de ambiente
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

app = FastAPI()

# Criptografando a senha no banco de dados
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_schema = OAuth2PasswordBearer(tokenUrl="auth/login-form")

# Tem que ser criado depois de app = FastAPI() para não dar erro de importação circular
from auth_routes import auth_router
from order_routes import order_router

# incluir no site todas as rotas do auth_router e order_router por meio do arquivo main.py
app.include_router(auth_router)
app.include_router(order_router)


