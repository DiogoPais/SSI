"""
server/auth.py
--------------
Registo, autenticação challenge-response e emissão/verificação de JWT.

Todas as funções recebem explicitamente o estado de que precisam
(users_db, active_challenges, …) em vez de o lerem de globais,
tornando-as mais fáceis de testar isoladamente.

"""

import os
import datetime
import jwt

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

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
        auth_pub_key = payload["auth_pub_key"]    # Ed25519 pública (hex)
        chat_pub_key = payload["chat_pub_key"]    # X25519  pública (hex)
    except KeyError:
        return {"status": "error", "reason": "Formato de registo inválido."}

    # Validar que auth_pub_key é realmente uma chave Ed25519 bem formada
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(auth_pub_key))
    except Exception:
        return {"status": "error", "reason": "Chave de autenticação inválida."}

    cert = assinar_certificado(ca_priv_key, username, chat_pub_key)
    users_db[username] = {
        "auth_pub_key": auth_pub_key,   # substitui salt+hash
        "chat_pub_key": chat_pub_key,
        "cert":         cert,
    }
    print(f"[SERVIDOR] Registado e certificado emitido: '{username}'")
    salvar_fn()
    return {"status": "ok", "message": f"'{username}' registado.", "cert": cert}


def handle_get_challenge(msg: dict,
                         users_db: dict,
                         active_challenges: dict) -> dict:
    """
    Emite um desafio aleatório de 32 bytes para o processo de login.

    """
    username = msg.get("username", "")
    if username not in users_db:
        return {"status": "error", "reason": "Utilizador não encontrado."}
    challenge = os.urandom(32)
    active_challenges[username] = challenge
    return {
        "status":    "ok",
        "challenge": challenge.hex(),
    }


def handle_login(msg: dict,
                 server_priv_key,
                 users_db: dict,
                 active_challenges: dict,
                 jwt_secret: bytes,
                 ca_pub_hex: str) -> dict:
    """
    Valida a assinatura Ed25519 sobre o desafio e emite um JWT.

    """
    username = msg.get("username", "")
    if username not in users_db or username not in active_challenges:
        return {"status": "error", "reason": "Desafio não iniciado ou utilizador desconhecido."}

    try:
        payload = desencriptar_payload(
            server_priv_key, msg["pub_key"], msg["nonce"], msg["cifra"])
    except Exception:
        return {"status": "error", "reason": "Falha na desencriptação."}

    challenge = active_challenges.pop(username)
    signature_hex = payload.get("signature", "")

    if not signature_hex:
        return {"status": "error", "reason": "Assinatura em falta no payload de login."}

    try:
        auth_pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(users_db[username]["auth_pub_key"]))
        auth_pub.verify(bytes.fromhex(signature_hex), challenge)
    except (InvalidSignature, Exception):
        return {"status": "error", "reason": "Credenciais inválidas."}

    print(f"[SERVIDOR] Login (Ed25519 verificado): '{username}'")
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