"""
server/handlers.py
------------------
Handlers de negócio do servidor: mensagens diretas, grupos e sinalização P2P.

Todas as funções recebem o estado necessário como parâmetros explícitos,
sem depender de variáveis globais (facilita testes e reutilização).
"""

import os
import json
import asyncio

from server.auth import verificar_token


# ---------- Mensagem direta -------------------------------------------- #

async def handle_msg(msg: dict,
                     users_db: dict,
                     users_ativos: dict,
                     offline_queue: dict,
                     jwt_secret: bytes,
                     salvar_fn) -> dict:
    try:
        remetente = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    destinatario = msg.get("to")
    if destinatario not in users_db:
        return {"status": "error", "reason": "Destinatário não existe."}

    payload_deliver = {
        "action":  "deliver",
        "from":    remetente,
        "data":    msg["data"],
        "pub_key": users_db[remetente]["chat_pub_key"],
        "cert":    users_db[remetente].get("cert", ""),
    }

    if destinatario in users_ativos:
        asyncio.create_task(
            users_ativos[destinatario].send(json.dumps(payload_deliver)))
        return {"status": "ok", "message": "Entregue."}
    else:
        offline_queue.setdefault(destinatario, []).append(payload_deliver)
        salvar_fn()
        print(f"[SERVIDOR] Mensagem offline para '{destinatario}'.")
        return {"status": "ok", "message": "Destinatário offline. Mensagem guardada."}


# ---------- Grupos ------------------------------------------------------ #

def handle_create_group(msg: dict,
                        users_db: dict,
                        users_ativos: dict,
                        groups: dict,
                        offline_queue: dict,
                        jwt_secret: bytes,
                        salvar_fn) -> dict:
    try:
        creator = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    group_name = msg.get("name", "").strip()
    members    = msg.get("members", [])
    key_shares = msg.get("key_shares", {})

    if not group_name:
        return {"status": "error", "reason": "Nome do grupo em falta."}
    if creator not in members:
        members = [creator] + members
    for m in members:
        if m not in users_db:
            return {"status": "error", "reason": f"Membro '{m}' não existe."}

    group_id = os.urandom(8).hex()
    groups[group_id] = {
        "name":       group_name,
        "members":    members,
        "key_shares": key_shares,
        "creator":    creator,
    }

    # Enviar convite automático a cada membro (online ou offline)
    for m in members:
        if m == creator:
            continue
        invite_payload = {
            "action":    "group_invite",
            "group_id":  group_id,
            "name":      group_name,
            "members":   members,
            "key_share": key_shares.get(m, ""),
        }
        if m in users_ativos:
            asyncio.create_task(users_ativos[m].send(json.dumps(invite_payload)))
        else:
            offline_queue.setdefault(m, []).append(invite_payload)

    salvar_fn()
    print(f"[SERVIDOR] Grupo '{group_name}' criado ({group_id}) por '{creator}'.")
    return {"status": "ok", "group_id": group_id, "name": group_name}


def handle_get_group_key(msg: dict,
                         groups: dict,
                         jwt_secret: bytes) -> dict:
    try:
        username = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    group_id = msg.get("group_id")
    if group_id not in groups:
        return {"status": "error", "reason": "Grupo não encontrado."}
    g = groups[group_id]
    if username not in g["members"]:
        return {"status": "error", "reason": "Não és membro deste grupo."}

    return {
        "status":    "ok",
        "key_share": g["key_shares"].get(username, ""),
        "members":   g["members"],
        "name":      g["name"],
    }


def handle_list_groups(msg: dict,
                       groups: dict,
                       jwt_secret: bytes) -> dict:
    try:
        username = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    result = {
        gid: {"name": g["name"], "members": g["members"]}
        for gid, g in groups.items()
        if username in g["members"]
    }
    return {"status": "ok", "groups": result}


async def handle_group_msg(msg: dict,
                           groups: dict,
                           users_ativos: dict,
                           offline_queue: dict,
                           jwt_secret: bytes,
                           salvar_fn) -> dict:
    try:
        remetente = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    group_id = msg.get("group_id")
    if group_id not in groups:
        return {"status": "error", "reason": "Grupo não encontrado."}
    g = groups[group_id]
    if remetente not in g["members"]:
        return {"status": "error", "reason": "Não és membro deste grupo."}

    payload_deliver = {
        "action":   "group_deliver",
        "group_id": group_id,
        "from":     remetente,
        "data":     msg["data"],
    }
    delivered, queued = 0, 0
    for member in g["members"]:
        if member == remetente:
            continue
        if member in users_ativos:
            asyncio.create_task(
                users_ativos[member].send(json.dumps(payload_deliver)))
            delivered += 1
        else:
            offline_queue.setdefault(member, []).append(payload_deliver)
            queued += 1

    if queued:
        salvar_fn()
    return {"status": "ok", "message": f"Entregue: {delivered}, offline: {queued}."}


# ---------- P2P relay --------------------------------------------------- #

async def handle_p2p_signal(msg: dict,
                             users_ativos: dict,
                             jwt_secret: bytes) -> dict:
    """
    Canal de sinalização P2P: repassa o payload ao destinatário sem inspecionar
    o conteúdo (que já chega cifrado E2EE).
    """
    try:
        remetente = verificar_token(msg.get("token", ""), jwt_secret)
    except ValueError as e:
        return {"status": "error", "reason": str(e)}

    destinatario = msg.get("to")
    if destinatario not in users_ativos:
        return {"status": "error", "reason": "Destinatário não está online para P2P."}

    signal_payload = {
        "action": "p2p_signal",
        "from":   remetente,
        "data":   msg.get("data"),
    }
    asyncio.create_task(
        users_ativos[destinatario].send(json.dumps(signal_payload)))
    return {"status": "ok"}