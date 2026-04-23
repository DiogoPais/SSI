"""
common/ratchet.py
-----------------
Implementacao do Double Ratchet (inspirado no Signal Protocol).

Combina dois mecanismos de avanco de chave:

  1. DH Ratchet (Diffie-Hellman Ratchet)
     A cada nova ronda de envio, gera-se um par X25519 efemero.
     O shared secret desse par alimenta a root key, que deriva novas
     chain keys de envio e recepcao.
     Garante: break-in recovery -- se um atacante comprometer a chain key
     num dado momento, perde acesso assim que o DH ratchet rodar.

  2. Symmetric Ratchet
     Dentro de cada ronda DH, a chain key avanca mensagem a mensagem
     usando HKDF. Cada mensagem usa uma message key diferente, descartada
     apos uso.
     Garante: forward secrecy -- mensagens passadas nao podem ser decifradas
     mesmo que a chain key atual seja comprometida.

Formato do payload cifrado:
  nonce(12) | dh_pub_raw(32) | seq(4) | ciphertext
  O header (dh_pub + seq) e autenticado como AAD pelo AES-GCM.

Cache de mensagens fora de ordem:
  Se uma mensagem chega com seq > recv_seq + 1, as chaves das mensagens
  saltadas sao guardadas em 'skipped' e usadas quando chegarem.
  Previne ataques de replay: mensagens com seq <= recv_seq sao rejeitadas.
"""

import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption

from common.protocol import (
    MAX_SKIP,
    HKDF_INFO_ROOT_KEY,
    HKDF_INFO_MSG_KEY,
    HKDF_INFO_CHAIN_KEY,
)


# ---------- KDFs internas ---------------------------------------------- #

def _hkdf(ikm: bytes, length: int, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), length, salt=None, info=info).derive(ikm)


def _kdf_rk(root_key: bytes, dh_out: bytes) -> tuple:
    """
    Deriva nova (root_key, chain_key) a partir do output DH.
    Mistura dh_out com root_key para que a entropia acumule.
    """
    out = _hkdf(dh_out + root_key, 64, HKDF_INFO_ROOT_KEY)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> tuple:
    """
    Avanca a chain key e deriva uma message key.
    Devolve (nova_chain_key, message_key).
    A message key e descartada apos uso -- nunca e guardada em disco
    apos a mensagem ser processada (excepto na cache de mensagens saltadas).
    """
    msg_key = _hkdf(chain_key, 32, HKDF_INFO_MSG_KEY)
    new_ck  = _hkdf(chain_key, 32, HKDF_INFO_CHAIN_KEY)
    return new_ck, msg_key


# ---------- RatchetState ----------------------------------------------- #

class RatchetState:
    """
    Estado completo de uma sessao Double Ratchet entre dois peers.
    Uma instancia por par (eu, peer) -- nao e partilhada.
    """

    def __init__(
            self,
            shared_secret: bytes,
            send_seq: int = 0,
            recv_seq: int = 0,
            is_initiator: bool = True,
            my_static_priv: X25519PrivateKey = None,
            peer_static_pub_hex: str = None,
            # campos opcionais para restauro a partir do disco
            root_key: bytes = None,
            send_chain_key: bytes = None,
            recv_chain_key: bytes = None,
            dh_send_priv_hex: str = None,
            dh_recv_pub_hex: str = None,
            skipped: dict = None,
            dh_ratchet_count: int = 0,
    ):
        if root_key is None:
            # Sessao nova -- inicializa a partir do shared_secret ECDH inicial
            self.root_key = shared_secret

            if is_initiator:
                # Iniciador: gera efemera, usa chave estática do destinatário para o 1º passo
                priv = X25519PrivateKey.generate()
                self.dh_send_priv = priv
                self.dh_send_pub_hex = priv.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                self.dh_recv_pub_hex = peer_static_pub_hex

                # Passo DH inicial para derivar a send_chain_key
                peer_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_static_pub_hex))
                dh_out = self.dh_send_priv.exchange(peer_pub)
                self.root_key, self.send_chain_key = _kdf_rk(self.root_key, dh_out)
                self.recv_chain_key = None
            else:
                # Recetor: usa a sua chave estática como primeira chave de envio
                # para que a troca ECDH bata certo com a do iniciador.
                self.dh_send_priv = my_static_priv
                self.dh_send_pub_hex = self.dh_send_priv.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                self.dh_recv_pub_hex = None
                self.send_chain_key = None
                self.recv_chain_key = None
        else:
            # Restauro do disco
            self.root_key = root_key
            self.send_chain_key = send_chain_key
            self.recv_chain_key = recv_chain_key
            self.dh_send_priv = X25519PrivateKey.from_private_bytes(
                bytes.fromhex(dh_send_priv_hex)) if dh_send_priv_hex else None
            self.dh_send_pub_hex = self.dh_send_priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() \
                if self.dh_send_priv else None
            self.dh_recv_pub_hex = dh_recv_pub_hex

        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.dh_ratchet_count = dh_ratchet_count

        # Cache: (dh_pub_hex, seq) -> msg_key
        self.skipped: dict[tuple, bytes] = {}
        if skipped:
            for k, v in skipped.items():
                parts = k.split("|")
                self.skipped[(parts[0], int(parts[1]))] = bytes.fromhex(v)

    # ---- DH Ratchet --------------------------------------------------- #

    def _dh_ratchet_recv(self, their_pub_hex: str):
        """
        Executa um passo do DH Ratchet ao receber uma nova chave publica.

        Passo 1: deriva recv_chain_key com o par DH atual + chave do peer.
        Passo 2: gera novo par DH de envio e deriva send_chain_key.

        Apos este passo, o par DH anterior e descartado -- nao pode ser
        recuperado, o que garante forward secrecy ao nivel do DH ratchet.
        """
        their_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(their_pub_hex))

        # Passo 1 -- recv chain key
        dh_out = self.dh_send_priv.exchange(their_pub)
        self.root_key, self.recv_chain_key = _kdf_rk(self.root_key, dh_out)
        self.dh_recv_pub_hex = their_pub_hex

        # Passo 2 -- novo par DH de envio + send chain key
        new_priv = X25519PrivateKey.generate()
        self.dh_send_priv    = new_priv
        self.dh_send_pub_hex = new_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        dh_out2 = self.dh_send_priv.exchange(their_pub)
        self.root_key, self.send_chain_key = _kdf_rk(self.root_key, dh_out2)

        self.recv_seq = 0
        self.dh_ratchet_count += 1

    # ---- Symmetric Ratchet -------------------------------------------- #

    def _advance_send(self) -> bytes:
        self.send_chain_key, msg_key = _kdf_ck(self.send_chain_key)
        return msg_key

    def _advance_recv(self) -> bytes:
        self.recv_chain_key, msg_key = _kdf_ck(self.recv_chain_key)
        return msg_key

    def _guardar_chaves_saltadas(self, their_pub_hex: str, ate_seq: int):
        """
        Avanca o ratchet simetrico e guarda as message keys das mensagens
        que ainda nao chegaram (vieram fora de ordem).
        Limita o numero de chaves guardadas a MAX_SKIP para evitar ataques
        de exaustao de memoria.
        """
        if self.recv_chain_key is None:
            return
        n_a_saltar = ate_seq - self.recv_seq
        if n_a_saltar > MAX_SKIP:
            raise ValueError(
                f"Demasiadas mensagens saltadas ({n_a_saltar} > {MAX_SKIP}). "
                "Sessao pode estar corrompida."
            )
        while self.recv_seq < ate_seq:
            self.recv_seq += 1
            self.recv_chain_key, msg_key = _kdf_ck(self.recv_chain_key)
            self.skipped[(their_pub_hex, self.recv_seq)] = msg_key

    # ---- API publica -------------------------------------------------- #

    def encrypt(self, plaintext: str) -> bytes:
        """
        Cifra 'plaintext' e avanca o ratchet simetrico de envio.

        Formato do payload:
          nonce(12) | dh_pub_raw(32) | seq(4) | ciphertext

        O header (dh_pub_raw + seq) e passado como AAD ao AES-GCM,
        o que garante que nao pode ser adulterado sem invalidar o MAC.
        """
        msg_key  = self._advance_send()
        self.send_seq += 1

        nonce    = os.urandom(12)
        seq_b    = struct.pack("!I", self.send_seq)
        dh_pub_b = bytes.fromhex(self.dh_send_pub_hex)
        header   = dh_pub_b + seq_b          # 36 bytes autenticados como AAD

        ct = AESGCM(msg_key).encrypt(nonce, plaintext.encode("utf-8"), header)
        return nonce + header + ct

    def decrypt(self, payload: bytes) -> str:
        """
        Decifra um payload e avanca o ratchet simetrico de recepcao.
        Executa DH ratchet se a chave publica do remetente mudou.
        Usa a cache para mensagens fora de ordem.
        Levanta ValueError em caso de replay ou payload corrompido.
        """
        if len(payload) < 48:
            raise ValueError("Payload demasiado curto.")

        nonce            = payload[:12]
        dh_pub_b         = payload[12:44]
        seq_b            = payload[44:48]
        ct               = payload[48:]
        their_pub_hex    = dh_pub_b.hex()
        msg_seq          = struct.unpack("!I", seq_b)[0]
        header           = dh_pub_b + seq_b

        # 1. Mensagem da cache (chegou fora de ordem anteriormente)
        cache_key = (their_pub_hex, msg_seq)
        if cache_key in self.skipped:
            msg_key = self.skipped.pop(cache_key)
            return AESGCM(msg_key).decrypt(nonce, ct, header).decode("utf-8")

        # 2. DH ratchet se a chave publica mudou
        if their_pub_hex != self.dh_recv_pub_hex:
            if self.recv_chain_key is not None:
                # Guardar chaves da ronda anterior que ainda nao chegaram
                self._guardar_chaves_saltadas(
                    self.dh_recv_pub_hex or "", self.recv_seq)
            self._dh_ratchet_recv(their_pub_hex)
            self.recv_seq = 0

        # 3. Prevencao de replay
        if msg_seq <= self.recv_seq:
            raise ValueError(
                f"Replay Attack detetado! Mensagem {msg_seq} ja foi recebida "
                f"(recv_seq={self.recv_seq})."
            )

        # 4. Mensagens perdidas -- guardar chaves na cache
        if msg_seq > self.recv_seq + 1:
            print(f"[RATCHET] Mensagens perdidas: esperado {self.recv_seq + 1}, "
                  f"recebido {msg_seq}. A guardar {msg_seq - self.recv_seq - 1} chaves.")
            self._guardar_chaves_saltadas(their_pub_hex, msg_seq - 1)

        # 5. Avanca ratchet simetrico e decifra
        msg_key       = self._advance_recv()
        self.recv_seq = msg_seq
        return AESGCM(msg_key).decrypt(nonce, ct, header).decode("utf-8")

    # ---- Serializacao ------------------------------------------------- #

    def to_dict(self) -> dict:
        """Serializa o estado completo para guardar em disco (cifrado)."""
        return {
            "root_key":         self.root_key.hex(),
            "send_chain_key":   self.send_chain_key.hex() if self.send_chain_key else None,
            "recv_chain_key":   self.recv_chain_key.hex() if self.recv_chain_key else None,
            "dh_send_priv_hex": self.dh_send_priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                NoEncryption()).hex() if self.dh_send_priv else None,
            "dh_recv_pub_hex":  self.dh_recv_pub_hex,
            "send_seq":         self.send_seq,
            "recv_seq":         self.recv_seq,
            "dh_ratchet_count": self.dh_ratchet_count,
            # Chave da cache: "dh_pub_hex|seq" -> msg_key_hex
            "skipped": {
                f"{k[0]}|{k[1]}": v.hex()
                for k, v in self.skipped.items()
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetState":
        """Restaura o estado a partir de um dict (lido do disco)."""
        return cls(
            shared_secret    = bytes.fromhex(d["root_key"]),
            root_key         = bytes.fromhex(d["root_key"]),
            send_chain_key   = bytes.fromhex(d["send_chain_key"])
                               if d.get("send_chain_key") else None,
            recv_chain_key   = bytes.fromhex(d["recv_chain_key"])
                               if d.get("recv_chain_key") else None,
            dh_send_priv_hex = d.get("dh_send_priv_hex"),
            dh_recv_pub_hex  = d.get("dh_recv_pub_hex"),
            send_seq         = d.get("send_seq", 0),
            recv_seq         = d.get("recv_seq", 0),
            dh_ratchet_count = d.get("dh_ratchet_count", 0),
            skipped          = d.get("skipped", {}),
        )