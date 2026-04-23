"""
server/persistence.py
---------------------
Guardar e carregar o estado cifrado do servidor em disco.

O ficheiro é cifrado com AES-GCM, cuja chave é derivada via PBKDF2
a partir da password mestre do servidor.
"""

import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption

from common.crypto import pbkdf2_derive
from common.protocol import DB_FILE


def salvar_estado(master_password: str,
                  server_priv_key: X25519PrivateKey,
                  ca_priv_key: Ed25519PrivateKey,
                  jwt_secret: bytes,
                  users_db: dict,
                  offline_queue: dict,
                  groups: dict) -> None:
    """Serializa e cifra todo o estado do servidor para DB_FILE."""
    estado = {
        "server_priv_key": server_priv_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            NoEncryption()).hex(),
        "ca_priv_key": ca_priv_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            NoEncryption()).hex(),
        "jwt_secret":   jwt_secret.hex(),
        "users_db": {
            u: {
                "salt":         d["salt"].hex(),
                "hash":         d["hash"].hex(),
                "chat_pub_key": d["chat_pub_key"],
                "cert":         d.get("cert", ""),
            }
            for u, d in users_db.items()
        },
        "offline_queue": offline_queue,
        "groups":        groups,
    }
    estado_json = json.dumps(estado).encode()
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = pbkdf2_derive(master_password, salt)
    ct    = AESGCM(key).encrypt(nonce, estado_json, None)

    fd = os.open(DB_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(salt + nonce + ct)


def carregar_estado(master_password: str) -> dict:
    """
    Lê e decifra o estado do servidor.
    Devolve o dict deserializado ou levanta Exception em caso de falha.
    """
    with open(DB_FILE, "rb") as f:
        dados = f.read()
    salt, nonce, ct = dados[:16], dados[16:28], dados[28:]
    key    = pbkdf2_derive(master_password, salt)
    estado = json.loads(AESGCM(key).decrypt(nonce, ct, None).decode())
    return estado


def reconstruir_users_db(raw: dict) -> dict:
    """Converte os campos hex do users_db de volta para bytes."""
    return {
        u: {
            "salt":         bytes.fromhex(d["salt"]),
            "hash":         bytes.fromhex(d["hash"]),
            "chat_pub_key": d["chat_pub_key"],
            "cert":         d.get("cert", ""),
        }
        for u, d in raw.items()
    }