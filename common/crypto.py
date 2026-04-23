"""
common/crypto.py
----------------
Primitivas criptográficas partilhadas entre cliente e servidor.

Inclui:
  - HKDF / PBKDF2
  - Cifra/decifra AES-GCM com chave ECDH efémera
  - Derivação de chave de transporte E2EE
"""

import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


# ---------- KDFs -------------------------------------------------------- #

def hkdf_derive(ikm: bytes, length: int, info: bytes) -> bytes:
    """Deriva 'length' bytes a partir de 'ikm' usando HKDF-SHA256."""
    return HKDF(hashes.SHA256(), length, salt=None, info=info).derive(ikm)


def pbkdf2_derive(password: str, salt: bytes, length: int = 32,
                  iterations: int = 600_000) -> bytes:
    """Deriva uma chave a partir de uma password com PBKDF2-SHA256."""
    return PBKDF2HMAC(hashes.SHA256(), length, salt, iterations).derive(
        password.encode())


# ---------- Transporte E2EE (cliente ↔ servidor) ----------------------- #

def derivar_chave_aes(shared: bytes) -> bytes:
    """Deriva chave AES-256 a partir do shared secret ECDH de transporte."""
    return hkdf_derive(shared, 32, b"e2ee-transport-v1")


def encriptar_payload(server_pub_hex: str, payload: dict) -> tuple[str, str, str]:
    """
    Cifra 'payload' para o servidor usando ECDH efémero + AES-GCM.
    Devolve (pub_hex, nonce_hex, cifra_hex).
    """
    priv       = X25519PrivateKey.generate()
    pub_hex    = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    server_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(server_pub_hex))
    shared     = priv.exchange(server_pub)
    aes_key    = derivar_chave_aes(shared)
    nonce      = os.urandom(12)
    ct         = AESGCM(aes_key).encrypt(nonce, json.dumps(payload).encode(), None)
    return pub_hex, nonce.hex(), ct.hex()


def desencriptar_payload(server_priv_key: X25519PrivateKey,
                         pub_hex: str, nonce_hex: str, cifra_hex: str) -> dict:
    """
    Decifra um payload recebido pelo servidor.
    'server_priv_key' é a chave privada X25519 do servidor.
    """
    client_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    shared     = server_priv_key.exchange(client_pub)
    aes_key    = derivar_chave_aes(shared)
    plaintext  = AESGCM(aes_key).decrypt(
        bytes.fromhex(nonce_hex), bytes.fromhex(cifra_hex), None)
    return json.loads(plaintext.decode())


# ---------- Cifra de chave de grupo ------------------------------------ #

def cifrar_chave_grupo(group_key: bytes, peer_pub_hex: str) -> str:
    """
    Cifra 'group_key' para um membro usando ECDH efémero.
    Devolve "eph_pub_hex.nonce_hex.ct_hex".
    """
    peer_pub  = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
    ephemeral = X25519PrivateKey.generate()
    shared    = ephemeral.exchange(peer_pub)
    kek       = hkdf_derive(shared, 32, b"group-key-wrap-v1")
    nonce     = os.urandom(12)
    ct        = AESGCM(kek).encrypt(nonce, group_key, None)
    eph_pub   = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return f"{eph_pub}.{nonce.hex()}.{ct.hex()}"


def decifrar_chave_grupo(key_share: str,
                         identity_priv: X25519PrivateKey) -> bytes:
    """
    Decifra uma key_share de grupo recebida pelo cliente.
    Devolve os bytes da chave de grupo em claro.
    """
    eph_pub_hex, nonce_hex, ct_hex = key_share.split(".")
    eph_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(eph_pub_hex))
    shared  = identity_priv.exchange(eph_pub)
    kek     = hkdf_derive(shared, 32, b"group-key-wrap-v1")
    return AESGCM(kek).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)