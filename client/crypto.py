"""
client/crypto.py
----------------
Funções criptográficas e de persistência do lado do cliente.

Inclui:
  - Inicialização de sessão Double Ratchet entre dois peers
  - Guardar / carregar o estado local cifrado em disco
"""

import os
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.ratchet import RatchetState


# ---------- Sessão Double Ratchet --------------------------------------- #

def iniciar_sessao_ratchet(my_username: str, peer_username: str,
                            shared_secret: bytes,
                            my_static_priv: X25519PrivateKey,
                            peer_static_pub_hex: str,
                            is_initiator: bool) -> RatchetState:
    """
    Cria um RatchetState a partir de um shared secret ECDH.
    O parâmetro is_initiator define se fomos nós a começar a conversa
    ou se estamos a responder à primeira mensagem recebida.
    """
    return RatchetState(
        shared_secret=shared_secret,
        is_initiator=is_initiator,
        my_static_priv=my_static_priv,
        peer_static_pub_hex=peer_static_pub_hex
    )

# ---------- Persistência local ----------------------------------------- #

def guardar_estado_local(username: str, password: str,
                          identity_priv: X25519PrivateKey,
                          sessions: dict,
                          trusted_keys: dict,
                          my_cert: str = "",
                          ca_pub_hex: str = "",
                          groups: dict = None) -> None:
    """
    Serializa e cifra o estado do cliente (chaves, sessões, grupos)
    para 'estado_<username>.bin'.
    A chave de cifragem é derivada da password via PBKDF2.
    """
    priv_hex = identity_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        NoEncryption()).hex()

    estado = {
        "identity_priv": priv_hex,
        "my_cert":       my_cert,
        "ca_pub_hex":    ca_pub_hex,
        "sessions":      {peer: r.to_dict() for peer, r in sessions.items()},
        "trusted_keys":  trusted_keys,
        "groups":        groups or {},
    }
    estado_json = json.dumps(estado).encode()
    salt  = os.urandom(16)
    kek   = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(password.encode())
    nonce = os.urandom(12)
    ct    = AESGCM(kek).encrypt(nonce, estado_json, None)

    filepath = f"estado_{username}.bin"
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(salt + nonce + ct)


def carregar_estado_local(username: str, password: str) -> tuple:
    """
    Lê e decifra o estado do cliente.
    Devolve (identity_priv, sessions, trusted_keys, my_cert, ca_pub_hex, groups).
    Levanta ValueError se o ficheiro não existir ou a password for incorreta.
    """
    filepath = f"estado_{username}.bin"
    try:
        with open(filepath, "rb") as f:
            dados = f.read()
    except FileNotFoundError:
        raise ValueError("Ficheiro de estado não encontrado. Registe-se primeiro.")

    salt, nonce, ct = dados[:16], dados[16:28], dados[28:]
    kek = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(password.encode())
    try:
        estado = json.loads(AESGCM(kek).decrypt(nonce, ct, None).decode())
    except Exception:
        raise ValueError("Password incorreta ou ficheiro corrompido.")

    identity_priv = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(estado["identity_priv"]))
    sessions = {
        peer: RatchetState.from_dict(d)
        for peer, d in estado["sessions"].items()
    }
    return (
        identity_priv,
        sessions,
        estado.get("trusted_keys", {}),
        estado.get("my_cert", ""),
        estado.get("ca_pub_hex", ""),
        estado.get("groups", {}),
    )