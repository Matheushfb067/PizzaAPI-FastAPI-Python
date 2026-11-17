from main import SECRET_KEY, ALGORITHM, oauth2_schema
from sqlalchemy.orm import sessionmaker, Session
from fastapi import Depends, HTTPException
from jose import jwt, JWTError
from models import User
from models import db 

def get_session():
    try: 
        Session = sessionmaker(bind=db) # Criando nova sessão do banco
        session = Session() # Abrindo nova sessão no banco de dados
        yield session
    finally:
        session.close()

'''
    Verify token precisa ser um dependencia, pois a rota precisa receber o usuario depois que o token foi validado. 
    Quando chega uma requisição para /refresh, o FastAPI executa verify_token primeiro. A dependência:
        1. Obtém o token de oauth2_schema.
        2. Decodifica e valida o token.
        3. Lê o sub e procura o usuário no banco.
        4. Devolve o usuário à rota.
    Se a validação falhar, verify_token lança HTTPException e o endpoint não é executado. Se passar, o usuário 
    retornado fica disponível como argumento user, e a rota pode usar user.id
'''

def verify_token(token: str = Depends(oauth2_schema), session: Session = Depends(get_session)):
    try:
        dict_info = jwt.decode(token, SECRET_KEY, ALGORITHM)
        id_user = int(dict_info.get("sub"))
    except JWTError: # se o erro for um JWTError, significa que a decodificação deu errado, ou seja, token invalido
        raise HTTPException(status_code=401, detail="Access Denied. Check the token`s validity")
    # Verificar se o token é valido
    # Extrair o id do token
    user =  session.query(User).filter(User.id == id_user).first()
    if not user: 
        raise HTTPException(status_code=401, detail="Invalid Access")
    return user