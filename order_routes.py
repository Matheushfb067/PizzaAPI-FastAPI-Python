from fastapi import APIRouter, Depends, HTTPException
from dependencies import get_session, verify_token
from sqlalchemy.orm import Session
from schemas import OrderSchema
from models import Order, User

''' 
    Todas as rotas de pedidos precisam de autenticação do usuário. Para isso usamos o parametro dependencies dentro da 
    variavel order_router, como uma lista, dento dela passamos o Depends(verify_token), o que garante que todos endpoints
    de pedidos sejam bloqueados, a menos que o token seja verificado pela função verify_token. Assim todos os endpoints 
    de pedidos estão automaticamente estão bloqueados seguindo o padrão OAuth2 definido.
'''

order_router = APIRouter(prefix="/orders", tags=["orders"], dependencies=[Depends(verify_token)])

@order_router.get("/") # @ = decorator
async def orders():
    """Essa é a rota padrão de pedidos do nosso sistema. """
    return {"mensagem": "Você acessou a rota de pedidos!"}

# IMPLEMENTAR MODIFICAçÃO DE QUE O USUARIO SÓ PODE FAZER UM PEDIDO PARA ELE MESMO, USANDO A LÓGICA DE order_cancelation DE PRIVILÉGIOS... 

@order_router.post("/order")
async def crate_order(order_schema: OrderSchema, session: Session = Depends(get_session)):
    new_order = Order(user = order_schema.user)
    session.add(new_order)
    session.commit()
    return {"Mensagem": f"Pedido criado com sucesso. ID do pedido: {new_order.id}"}

# Rota de cancelamento de pedidos: 
@order_router.post("/order/cancel/{order_id}") # Passamos order_id direto na url, por que para fazer o cancelamento do pedido iremos usar seu id, o que muda é quu o parametro será passado no path e não no body
async def order_cancellation(order_id: int, session: Session = Depends(get_session), user: User = Depends(verify_token)): # Passamos o User = Depends(verify_token) como paramentro da função, por que precisamos saber qual usuario está fazendo login, para determinar seu nivel de acesso
    
    # Primeiro precisamos pegar o pedido que tenha o id que queremos cancelar dentro do banco: 
    order = session.query(Order).filter(Order.id == order_id).first()
    if not order: 
        raise HTTPException(status_code=400, detail="Order not found")
    '''
        Somente o usuario dono do pedido, ou o admin do sistema são autorizados a cancelar o pedido para isso primeiramente precisamos saber 
        quem é o usuario (nivel de acesso) que está fazendo  a requisição. Regras para determinar se o usuario poderá fazer o cancelamento ou não: 
    
        1. user.admin = True
        2. user.id == order.user
    '''
    if not user.admin and user.id != order.user:
        raise HTTPException(status_code=401, detail="Você não tem autorização para fazer essa modificação")

    order.status = "CANCELADO"
    # Agora que pedido.status está cancelado, vamos atualizar o valor no banco de dados
    session.commit() # salva a edição feita dentro do banco de dados
    return {"Mensagem": f"Pedido numero: {order.id} cancelado com suscesso!", "pedido": order}