"""
client/crypto.py
----------------
Funções criptográficas e de persistência do lado do cliente.

Inclui:
  - Inicialização de sessão Double Ratchet entre dois peers
  - Guardar / carregar o estado local cifrado em disco

CORREÇÕES:
  Vulnerabilidade 1 — Pass-the-Hash / Autenticação insegura:
    O estado persistido inclui agora a chave privada Ed25519 de autenticação
    (auth_priv). Esta chave é DISTINTA da chave X25519 de chat (identity_priv)
    e serve exclusivamente para assinar o desafio de login. A chave pública
    correspondente é registada no servidor durante o registo.

  Vulnerabilidade 4 — Falta de Forward Secrecy no Handshake Inicial:
    A função iniciar_sessao_ratchet deixa de receber um 'shared_secret'
    calculado externamente. O RatchetState gera internamente o par efémero
    (iniciador) ou usa a chave estática (recetor), garantindo que o primeiro
    passo DH nunca usa static-static X25519.
"""

import os
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from common.ratchet import RatchetState


# ---------- Sessão Double Ratchet --------------------------------------- #

def iniciar_sessao_ratchet(my_username: str,
                            peer_username: str,
                            my_static_priv: X25519PrivateKey,
                            peer_static_pub_hex: str,
                            is_initiator: bool) -> RatchetState:
    """
    Cria um RatchetState para a sessão entre 'my_username' e 'peer_username'.

    CORREÇÃO Vulnerabilidade 4:
      O shared_secret inicial deixa de ser calculado aqui com static-static
      X25519. Em vez disso, passa-se shared_secret=b'\\x00'*32 como semente
      nula — o RatchetState irá sobrepô-la imediatamente no primeiro passo DH
      efémero (iniciador) ou aguardará o eph_pub do peer (recetor).
      O root_key real é assim sempre derivado de pelo menos uma chave efémera.
    """
    return RatchetState(
        shared_secret       = bytes(32),   # semente nula; sobreposta no 1.º DH
        is_initiator        = is_initiator,
        my_static_priv      = my_static_priv,
        peer_static_pub_hex = peer_static_pub_hex,
    )


# ---------- Persistência local ----------------------------------------- #

def guardar_estado_local(username: str,
                          password: str,
                          identity_priv: X25519PrivateKey,
                          auth_priv: Ed25519PrivateKey,
                          sessions: dict,
                          trusted_keys: dict,
                          my_cert: str = "",
                          ca_pub_hex: str = "",
                          groups: dict = None) -> None:
    """
    Serializa e cifra o estado do cliente (chaves, sessões, grupos)
    para 'estado_<username>.bin'.
    A chave de cifragem é derivada da password via PBKDF2.

    CORREÇÃO Vulnerabilidade 1:
      O campo 'auth_priv' (Ed25519) é agora persistido juntamente com a
      chave de chat X25519 ('identity_priv'). Ambas são cifradas com a
      mesma KEK derivada da password — nunca são guardadas em claro.
    """
    identity_priv_hex = identity_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        NoEncryption()).hex()

    auth_priv_hex = auth_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        NoEncryption()).hex()

    estado = {
        "identity_priv": identity_priv_hex,
        "auth_priv":     auth_priv_hex,          # NOVO: chave de autenticação Ed25519
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

    Devolve:
      (identity_priv, auth_priv, sessions, trusted_keys,
       my_cert, ca_pub_hex, groups)

    CORREÇÃO Vulnerabilidade 1:
      Devolve também 'auth_priv' (Ed25519) para que o ClienteWS possa
      assinar o desafio de login sem recalcular a chave.

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

    # Compatibilidade retroativa: ficheiros antigos sem 'auth_priv'
    if "auth_priv" in estado:
        auth_priv = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(estado["auth_priv"]))
    else:
        raise ValueError(
            "Estado sem chave de autenticação Ed25519. "
            "Registe-se novamente para migrar a conta.")

    sessions = {
        peer: RatchetState.from_dict(d)
        for peer, d in estado["sessions"].items()
    }
    return (
        identity_priv,
        auth_priv,
        sessions,
        estado.get("trusted_keys", {}),
        estado.get("my_cert", ""),
        estado.get("ca_pub_hex", ""),
        estado.get("groups", {}),
    )