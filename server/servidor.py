"""
server/server.py
----------------
Ponto de entrada do servidor de chat E2EE.

Responsabilidades:
  - Inicializar chaves e carregar/criar a base de dados cifrada.
  - Arrancar o servidor WebSocket com TLS.
  - Despachar cada mensagem recebida para o handler correto.
"""

import os
import ssl
import json
import getpass
import asyncio
import websockets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from common.protocol import DB_FILE, TLS_CERT, TLS_KEY
from server.persistence import salvar_estado, carregar_estado, reconstruir_users_db
from server.auth import (
    handle_register, handle_get_challenge, handle_login, handle_get_key,
)
from server.handlers import (
    handle_msg, handle_create_group, handle_list_groups,
    handle_get_group_key, handle_group_msg, handle_p2p_signal,
)


# ---------- Estado global do servidor ----------------------------------- #

server_priv_key:  X25519PrivateKey  = None
SERVER_PUB_HEX:   str               = None
ca_priv_key:      Ed25519PrivateKey = None
CA_PUB_HEX:       str               = None
JWT_SECRET_KEY:   bytes             = None
master_password:  str               = None

users_db:          dict = {}   # username -> {salt, hash, chat_pub_key, cert}
users_ativos:      dict = {}   # username -> websocket
active_challenges: dict = {}
offline_queue:     dict = {}   # username -> [payload, ...]
groups:            dict = {}   # group_id -> {name, members, key_shares}


# ---------- Função de persistência simplificada (passa estado atual) ---- #

def _salvar():
    salvar_estado(
        master_password, server_priv_key, ca_priv_key,
        JWT_SECRET_KEY, users_db, offline_queue, groups,
    )


# ---------- Inicialização ----------------------------------------------- #

def inicializar_servidor():
    global server_priv_key, SERVER_PUB_HEX, ca_priv_key, CA_PUB_HEX
    global JWT_SECRET_KEY, master_password, offline_queue, groups

    print("=== CHAT E2EE - ARRANQUE DO SERVIDOR ===")
    master_password = (
        os.environ.get("SERVER_PASSWORD")
        or getpass.getpass("[SERVIDOR] Password mestre: ")
    )

    if os.path.exists(DB_FILE):
        try:
            estado = carregar_estado(master_password)

            server_priv_key = X25519PrivateKey.from_private_bytes(
                bytes.fromhex(estado["server_priv_key"]))
            ca_priv_key     = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(estado["ca_priv_key"]))
            JWT_SECRET_KEY  = bytes.fromhex(estado["jwt_secret"])

            users_db.update(reconstruir_users_db(estado["users_db"]))
            offline_queue = estado.get("offline_queue", {})
            groups        = estado.get("groups", {})

            print(f"[SERVIDOR] Estado carregado. {len(users_db)} utilizadores, "
                  f"{len(groups)} grupos.")
        except Exception:
            print("[ERRO CRÍTICO] Falha ao desencriptar BD.")
            raise SystemExit(1)
    else:
        print("[SERVIDOR] A criar nova BD segura...")
        server_priv_key = X25519PrivateKey.generate()
        ca_priv_key     = Ed25519PrivateKey.generate()
        JWT_SECRET_KEY  = os.urandom(32)
        _salvar()
        print("[SERVIDOR] Nova BD criada.")

    SERVER_PUB_HEX = server_priv_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    CA_PUB_HEX = ca_priv_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    with open("ca_pinned.pub", "w") as f:
        f.write(CA_PUB_HEX)
    print(f"[CA] Chave pública: {CA_PUB_HEX[:16]}...")


# ---------- Handler WebSocket principal --------------------------------- #

async def handler(websocket):
    addr            = websocket.remote_address
    username_ligado = None
    print(f"[SERVIDOR] Cliente ligado: {addr}")

    assinatura = ca_priv_key.sign(bytes.fromhex(SERVER_PUB_HEX))

    await websocket.send(json.dumps({
        "type": "server_hello",
        "server_pub": SERVER_PUB_HEX,
        "ca_pub": CA_PUB_HEX,
        "sig": assinatura.hex(),
    }))

    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            action = msg.get("action")

            if action == "register":
                resposta = handle_register(
                    msg, server_priv_key, ca_priv_key, users_db, _salvar)

            elif action == "get_challenge":
                resposta = handle_get_challenge(msg, users_db, active_challenges)

            elif action == "login":
                resposta = handle_login(
                    msg, server_priv_key, users_db,
                    active_challenges, JWT_SECRET_KEY, CA_PUB_HEX)
                await websocket.send(json.dumps(resposta))
                if resposta.get("status") == "ok":
                    username_ligado = msg.get("username")
                    users_ativos[username_ligado] = websocket
                    pendentes = offline_queue.pop(username_ligado, [])
                    if pendentes:
                        print(f"[SERVIDOR] A entregar {len(pendentes)} msgs "
                              f"offline a '{username_ligado}'.")
                        for mp in pendentes:
                            await websocket.send(json.dumps(mp))
                        _salvar()
                continue

            elif action == "get_key":
                resposta = handle_get_key(msg, users_db, JWT_SECRET_KEY)

            elif action == "msg":
                resposta = await handle_msg(
                    msg, users_db, users_ativos, offline_queue,
                    JWT_SECRET_KEY, _salvar)

            elif action == "create_group":
                resposta = handle_create_group(
                    msg, users_db, users_ativos, groups,
                    offline_queue, JWT_SECRET_KEY, _salvar)

            elif action == "list_groups":
                resposta = handle_list_groups(msg, groups, JWT_SECRET_KEY)

            elif action == "get_group_key":
                resposta = handle_get_group_key(msg, groups, JWT_SECRET_KEY)

            elif action == "group_msg":
                resposta = await handle_group_msg(
                    msg, groups, users_ativos, offline_queue,
                    JWT_SECRET_KEY, _salvar)

            elif action == "p2p_signal":
                resposta = await handle_p2p_signal(
                    msg, users_ativos, JWT_SECRET_KEY)

            elif action == "ping":
                resposta = {"status": "ok", "message": "Pong!"}

            else:
                resposta = {"status": "error", "reason": "Action desconhecida."}

            await websocket.send(json.dumps(resposta))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username_ligado and users_ativos.get(username_ligado) is websocket:
            del users_ativos[username_ligado]
        print(f"[SERVIDOR] Desligado: {addr} ({username_ligado})")


# ---------- main -------------------------------------------------------- #

async def main():
    inicializar_servidor()

    if not os.path.exists(TLS_CERT) or not os.path.exists(TLS_KEY):
        print(f"[ERRO CRÍTICO] Certificado TLS não encontrado ({TLS_CERT}/{TLS_KEY}).")
        print(
            "  Gere com: openssl req -x509 -newkey rsa:4096 "
            f"-keyout {TLS_KEY} -out {TLS_CERT} -days 365 -nodes "
            '-subj "/CN=localhost" '
            '-addext "subjectAltName=IP:127.0.0.1,DNS:localhost"'
        )
        raise SystemExit(1)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(TLS_CERT, TLS_KEY)

    print("\n[SERVIDOR] A iniciar em wss://localhost:8765 (TLS activo)...")
    async with websockets.serve(handler, "localhost", 8765, ssl=ssl_ctx):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())