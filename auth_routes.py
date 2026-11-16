from fastapi import APIRouter, Depends, HTTPException # Permite organizar as rotas da API em diferentes arquivos ou módulos
from models import User
from dependencies import get_session, verify_token
from main import bcrypt_context, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY
from schemas import UserSchema, LoginSchema
from sqlalchemy.orm import Session
from jose import jwt, JWTError # Responsavel pela geração do token
from datetime import datetime, timedelta, timezone # Padrão do python para manipulação de tempo
from fastapi.security import OAuth2PasswordRequestForm

# Sempre definir um prefixo para as rotas para organizar o código
auth_router = APIRouter(prefix="/auth", tags=["auth"])

# Função auxiliar de criação de token
def create_token(user_id, token_duration = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    # JWT - JSON WEB TOKEN
    '''
    aqui iremos fazer a criação de um novo tocken, as informações necessarias serão o id do usuario e a data de 
    expiração do token. Existem duas formas de fazer essa nova geração de token, por meio de email e senha, ou por 
    refresh token, que permite gerar um novo token por tempo de autenticação. A forma mais atual de se fazer isso é 
    por meio do python-jose
    '''
    expiration_date = datetime.now(timezone.utc) + token_duration  
    dict_info = {"sub": str(user_id), "exp": expiration_date}
    encoded_jwt = jwt.encode(dict_info, SECRET_KEY, ALGORITHM) # Paramentros para gerar a codificação: Dicionario, chave secreta e algoritimo de codificação
    return encoded_jwt

# função de autenticação
def authenticate_user(email, password, session):
    user = session.query(User).filter(User.email==email).first()

    if not user:
        return False    
    elif not bcrypt_context.verify(password, user.password):
        return False
    
    return user

@auth_router.get("/")
async def home():
    """Essa é a rota padrão de autenticação do nosso sistema"""
    return {"mensagem": "Você acessou a rota de autenticação!", "autenticado": False}

'''
    O modelo de criação de usuario a baixo tem alguns problemas: 
    - A sessão não é fechada em momento nenhum
    - Só uma mensagem é retornada dentro do if enquanto dentro do if deveria retornar um código de erro http e dentro do else um código de sucesso
    - Estamos pegando parametros de forma despadronizada
    - A senha não está sendo criptografada

    O objetivo de termos feito inicialmente dessa forma é demonstrar como é a estrutura 
    de criação de usuario de forma direta e simples.
'''
'''
@auth_router.post("/create_user")
async def create_account(email: str, password: str, name: str):
    # Pesquisando na tabela de usuario se existe um usuario com esse e-mail
    # Para isso trazemos a tabela de usuarios de models para cá por meio da importação 

    Session = sessionmaker(bind=db) # Criando nova sessão do banco
    session = Session() # Abrindo nova sessão no banco de dados

    # Agora eu podemos fazer requisições dentro da tabela user uma vez que a sessão já foi criada
    user = session.query(User).filter(User.email==email).first() # .first() pega o primeiero usuario com o email que queremos filtrar
    if user: 
        return {"mensagem":"Já existe um usuario com esse email!"}
    else:
        # Caso o usuario não exista devemos criar um novo usuario
        # Para isso precisamos passar o nome, email e senha que foram definidos em models
        # Depois armazemos no banco por meio da sessão

        new_user = User(name, email, password, True, False)
        session.add(new_user) # Armazenando novo usuario criado no banco
        session.commit() # Salva as alterações no banco
        return {"mensagem": "Usuario cadastrado com sucesso!"}
'''

# Fazendo o gerenciamento de sessão de forma mais robusta
# Todas as rotas dependem de uma sessão, portanto, para não criarmos elas em todos os endpoints criamos uma dependencia
# criado no arquivo dependencies.py que conterá a minha sessão e o fechamento dessa sessão

@auth_router.post("/create_user")
async def create_account(user_schema: UserSchema, session: Session = Depends(get_session)):
    # Pesquisando na tabela de usuario se existe um usuario com esse e-mail
    # Para isso trazemos a tabela de usuarios de models para cá por meio da importação 
    
    #    Agora ao em vez de criarmos a sessão aqui diretamente, passamos ela como parametro 
    #    direto para a função crate_acount sem precisar importar db e nem sqlalchemy.orm sessionmaker
    #    uma vez que isso está importado no arquivo de dependencies, então só importamos o proprio 
    #    dependencies.
    
    # Agora eu podemos fazer requisições dentro da tabela user uma vez que a sessão já foi criada
    user = session.query(User).filter(User.email==user_schema.email).first() # .first() pega o primeiero usuario com o email que queremos filtrar
    if user:    
        # Fazendo a padronizão de código de respostas
        # Usando HTTPExeption para gerar códigos de erro http para requisições incorretas. Nesse caso o código 400
        # return HTTPException(status_code = 400, detail="E-mail já cadastrado!")
        # é costume usar o raise ao em vez de return, já que estamos levantando um erro e não retornando um dado
        raise HTTPException(status_code = 400, detail="E-mail já cadastrado!")
    else:

        # Cria uma hash a partir da senha que o usuario digitou
        encrypted_password = bcrypt_context.hash(user_schema.password)

        # Caso o usuario não exista devemos criar um novo usuario
        # Para isso precisamos passar o nome, email e senha que foram definidos em models
        # Depois armazemos no banco por meio da sessão

        new_user = User(user_schema.name, user_schema.email, encrypted_password, user_schema.active, user_schema.admin)
        session.add(new_user) # Armazenando novo usuario criado no banco
        session.commit() # Salva as alterações no banco

        return {"mensagem": f"Usuario cadastrado com sucesso! {user_schema.email}"}

# Proxima rota: login, faz sentido criarmos uma rota de login, uma vez que queremos apenas que usuarios logados possam fazer pedidos
# O processo de loging que se usa no fastAPI é o processo de uso de Tokens você loga apenas uma unica vez e esse token é usado em todas as rotas que estamos logados

# JWT

# login -> email e senha -> token JWT (Jsom Web token)

'''
    Access token: é enviado nas requisições protegidas. Costuma ter validade curta, limitando o tempo de uso caso seja exposto.
    Refresh token: é usado para pedir um novo access token quando o anterior expira, sem exigir que a pessoa faça login novamente. 
    Em geral, ele tem duração maior e precisa de controles próprios, como revogação e armazenamento seguro.
'''

@auth_router.post("/login")
async def login(login_schema: LoginSchema , session: Session = Depends(get_session)):
    user = authenticate_user(login_schema.email, login_schema.password, session)     
    if not user: 
        raise HTTPException(status_code=400, detail = "Usuario não encontrado ou credenciais invalidas!")
    else:
        access_token = create_token(user.id)
        refresh_token = create_token(user.id, token_duration=timedelta(days=7))
        return {
            "access_token": access_token, 
            "refresh_token": refresh_token,
            "token_type": "Bearer" # Padrão do token
            }

'''
    O botão Authorize aparece porque no main.py criamos um esquema OAuth2 e a função verify_token usa esse esquema como dependencia
    o fastAPI reconhece essa configuração como um requisito de autenticação e cria o botão de Authorize dentro do Swagger UI, para 
    que seja informado um token. A necessidade prática é testar endpoints protegidos pela documentação sem ter que adicionar o cabeçalho 
    manualmente a cada chamada.
'''
# A necessidade desse endpoint é oferecer o login no formato esperado pelo fluxo OAuth2 de senha do FastAPI.

@auth_router.post("/login-form")
async def login_form(form_data: OAuth2PasswordRequestForm = Depends() , session: Session = Depends(get_session)):
    user = authenticate_user(form_data.username, form_data.password, session)     
    if not user: 
        raise HTTPException(status_code=400, detail = "Usuario não encontrado ou credenciais invalidas!")
    else:
        access_token = create_token(user.id)
        return {
            "access_token": access_token, 
            "token_type": "Bearer" # Padrão do token
            }

# Geração de um novo refresh token
@auth_router.get("/refresh")
async def use_refresh_token(user: User = Depends(verify_token)):
    # Verificar Token
    access_token = create_token(user.id)
    return {
        "access_token": access_token, 
        "token_type": "Bearer" # Padrão do token - OAuth2
    }