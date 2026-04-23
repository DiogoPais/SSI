"""
server/auth.py
--------------
Registo, autenticação challenge-response e emissão/verificação de JWT.

Todas as funções recebem explicitamente o estado de que precisam
(users_db, active_challenges, …) em vez de o lerem de globais,
tornando-as mais fáceis de testar isoladamente.
"""

import os
import hmac
import hashlib
import datetime
import jwt

from common.crypto import desencriptar_payload
from common.pki import assinar_certificado


# ---------- JWT --------------------------------------------------------- #

def emitir_token(username: str, jwt_secret: bytes) -> str:
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    return jwt.encode(
        {"username": username, "exp": int(exp.timestamp())},
        jwt_secret, algorithm="HS256",
    )


def verificar_token(token: str, jwt_secret: bytes) -> str:
    """
    Valida o token e devolve o username.
    Levanta ValueError se o token for inválido ou expirado.
    """
    try:
        return jwt.decode(token, jwt_secret, algorithms=["HS256"])["username"]
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado.")
    except jwt.InvalidTokenError:
        raise ValueError("Token inválido.")


# ---------- Handlers de autenticação ------------------------------------ #

def handle_register(msg: dict,
                    server_priv_key,
                    ca_priv_key,
                    users_db: dict,
                    salvar_fn) -> dict:
    """
    Regista um novo utilizador.
    'salvar_fn' é chamada sem argumentos para persistir o estado após sucesso.
    """
    username = msg.get("username", "").strip()
    if not username:
        return {"status": "error", "reason": "Username em falta."}
    if username in users_db:
        return {"status": "error", "reason": "Utilizador já existe."}

    try:
        payload = desencriptar_payload(
            server_priv_key, msg["pub_key"], msg["nonce"], msg["cifra"])
    except Exception:
        return {"status": "error", "reason": "Falha na desencriptação."}

    try:
        client_salt  = bytes.fromhex(payload["salt"])
        client_hash  = bytes.fromhex(payload["hash"])
        chat_pub_key = payload["chat_pub_key"]
    except KeyError:
        return {"status": "error", "reason": "Formato de registo inválido."}

    cert = assinar_certificado(ca_priv_key, username, chat_pub_key)
    users_db[username] = {
        "salt":         client_salt,
        "hash":         client_hash,
        "chat_pub_key": chat_pub_key,
        "cert":         cert,
    }
    print(f"[SERVIDOR] Registado e certificado emitido: '{username}'")
    salvar_fn()
    return {"status": "ok", "message": f"'{username}' registado.", "cert": cert}


def handle_get_challenge(msg: dict,
                         users_db: dict,
                         active_challenges: dict) -> dict:
    """Emite um desafio aleatório para o processo de login."""
    username = msg.get("username", "")
    if username not in users_db:
        return {"status": "error", "reason": "Utilizador não encontrado."}
    challenge = os.urandom(32)
    active_challenges[username] = challenge
    return {
        "status":    "ok",
        "challenge": challenge.hex(),
        "salt":      users_db[username]["salt"].hex(),
    }


def handle_login(msg: dict,
                 server_priv_key,
                 users_db: dict,
                 active_challenges: dict,
                 jwt_secret: bytes,
                 ca_pub_hex: str) -> dict:
    """
    Valida a resposta HMAC ao desafio e emite um JWT.
    """
    username = msg.get("username", "")
    if username not in users_db or username not in active_challenges:
        return {"status": "error", "reason": "Desafio não iniciado."}

    try:
        payload = desencriptar_payload(
            server_priv_key, msg["pub_key"], msg["nonce"], msg["cifra"])
    except Exception:
        return {"status": "error", "reason": "Falha na desencriptação."}

    challenge       = active_challenges.pop(username)
    client_response = bytes.fromhex(payload.get("response", ""))
    stored_hash     = users_db[username]["hash"]
    expected        = hmac.new(stored_hash, challenge, hashlib.sha256).digest()

    if not hmac.compare_digest(client_response, expected):
        return {"status": "error", "reason": "Credenciais inválidas."}

    print(f"[SERVIDOR] Login: '{username}'")
    return {
        "status": "ok",
        "token":  emitir_token(username, jwt_secret),
        "ca_pub": ca_pub_hex,
        "cert":   users_db[username].get("cert", ""),
    }


def handle_get_key(msg: dict,
                   users_db: dict,
                   jwt_secret: bytes) -> dict:
    """Devolve a chave pública de chat de um utilizador (requer token válido)."""
    try:
        verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    target = msg.get("target")
    if target not in users_db:
        return {"status": "error", "reason": "Utilizador não encontrado."}

    return {
        "status":  "ok",
        "pub_key": users_db[target]["chat_pub_key"],
        "cert":    users_db[target].get("cert", ""),
    }