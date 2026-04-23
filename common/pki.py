"""
common/pki.py
-------------
PKI minimalista partilhada entre cliente e servidor.

O servidor usa 'assinar_certificado' para emitir certificados Ed25519.
O cliente usa 'verificar_certificado' para validar a chave pública de um peer.
"""

import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


def assinar_certificado(ca_priv_key: Ed25519PrivateKey,
                        username: str, chat_pub_hex: str) -> str:
    """
    Emite um certificado simples:
      payload = "username|chat_pub_hex|timestamp"
      assinatura Ed25519 sobre o payload

    Devolve "payload_hex.sig_hex".
    """
    ts      = str(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    payload = f"{username}|{chat_pub_hex}|{ts}".encode()
    sig     = ca_priv_key.sign(payload)
    return payload.hex() + "." + sig.hex()


def verificar_certificado(cert: str, ca_pub_hex: str) -> tuple[str, str]:
    """
    Verifica a assinatura Ed25519 da CA.
    Devolve (username, chat_pub_hex) se válido.
    Levanta ValueError se o certificado for inválido ou adulterado.
    """
    try:
        payload_hex, sig_hex = cert.split(".")
        payload = bytes.fromhex(payload_hex)
        sig     = bytes.fromhex(sig_hex)
        ca_pub  = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ca_pub_hex))
        ca_pub.verify(sig, payload)
        parts   = payload.decode().split("|")
        return parts[0], parts[1]   # username, chat_pub_hex
    except Exception:
        raise ValueError("Certificado inválido ou adulterado.")