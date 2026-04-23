"""
client/ws_client.py
-------------------
Classe ClienteWS: toda a lógica de rede e criptografia do cliente.

Separa claramente o "quê" (protocolo, sessões ratchet, grupos, P2P)
do "como" se interage (CLI, que fica em cli.py).
"""

import os
import ssl
import json
import hmac
import hashlib
import asyncio
import websockets
import struct
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from common.ratchet import _kdf_ck
from common.ratchet import RatchetState
from common.pki import verificar_certificado
from common.crypto import (
    encriptar_payload, cifrar_chave_grupo, decifrar_chave_grupo,
)
from common.protocol import SERVER_URL, TLS_CERT
from client.crypto import (
    iniciar_sessao_ratchet,
    guardar_estado_local,
    carregar_estado_local,
)


class ClienteWS:
    def __init__(self, uri: str = SERVER_URL):
        self.uri              = uri
        self.ws               = None
        self.server_pub       = None
        self.ca_pub_hex       = None
        self._cmd_future      = None
        self._escuta_task     = None

        self._send_lock = asyncio.Lock()

        self.identity_priv:    X25519PrivateKey | None        = None
        self.identity_pub_hex: str | None                     = None
        self.my_cert:          str                            = ""
        self.sessions:         dict[str, RatchetState]        = {}
        self.trusted_keys:     dict[str, str]                 = {}
        self.groups:           dict[str, dict]                = {}

        self._username_atual:  str | None = None
        self._password_atual:  str | None = None
        self._token:           str | None = None

        # P2P
        self._p2p_server = None
        self._p2p_peers: dict[str, websockets.WebSocketClientProtocol] = {}
        self._expected_p2p_tokens: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    #  Ligação TLS                                                         #
    # ------------------------------------------------------------------ #

    async def __aenter__(self):
        try:
            with open("ca_pinned.pub", "r") as f:
                CA_PIN = f.read().strip()
        except FileNotFoundError:
            raise FileNotFoundError(
                "[ERRO] O ficheiro 'ca_pinned.pub' não existe. "
                "Por favor, arranque o servidor primeiro para gerar a CA!"
            )
        if not os.path.exists(TLS_CERT):
            raise FileNotFoundError(
                f"Certificado '{TLS_CERT}' não encontrado. "
                "Copie o server.crt do servidor para esta pasta.")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.load_verify_locations(TLS_CERT)
        ssl_ctx.check_hostname = False

        self.ws = await websockets.connect(self.uri, ssl=ssl_ctx)
        raw = await self.ws.recv()
        msg = json.loads(raw)

        server_pub_hex = msg.get("server_pub")
        ca_recebida = msg.get("ca_pub")
        assinatura_hex = msg.get("sig")

        if ca_recebida != CA_PIN:
            await self.ws.close()
            raise ValueError("[ALERTA MITM] A CA do servidor não corresponde à CA oficial!")

        if not assinatura_hex:
            await self.ws.close()
            raise ValueError("[ALERTA MITM] O servidor não forneceu assinatura de identidade!")

        try:
            ca_pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(CA_PIN))
            ca_pub_key.verify(bytes.fromhex(assinatura_hex), bytes.fromhex(server_pub_hex))
        except InvalidSignature:
            await self.ws.close()
            raise ValueError("[ALERTA MITM] A assinatura do servidor é falsa! Possível interceção.")

        self.server_pub = server_pub_hex
        self.ca_pub_hex = CA_PIN

        print(f"[CLIENTE] Ligação E2EE estabelecida (Identidade validada contra CA Oficial).")
        return self

    async def __aexit__(self, *_):
        if self._escuta_task:
            self._escuta_task.cancel()
        if self._p2p_server:
            self._p2p_server.close()
        for ws in self._p2p_peers.values():
            await ws.close()
        if self.ws:
            await self.ws.close()

    # ------------------------------------------------------------------ #
    #  Loop de escuta (mensagens push do servidor)                         #
    # ------------------------------------------------------------------ #

    async def _escutar(self):
        try:
            async for raw in self.ws:
                msg    = json.loads(raw)
                action = msg.get("action")
                if action == "deliver":
                    await self._processar_deliver(msg)
                elif action == "group_deliver":
                    await self._processar_group_deliver(msg)
                elif action == "group_invite":
                    await self._processar_group_invite(msg)
                elif action == "p2p_signal":
                    await self._processar_p2p_signal(msg)
                elif self._cmd_future and not self._cmd_future.done():
                    self._cmd_future.set_result(msg)
        except websockets.exceptions.ConnectionClosed:
            print("\n[CLIENTE] Ligação ao servidor encerrada.")
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------ #
    #  Processamento de mensagens recebidas                                #
    # ------------------------------------------------------------------ #

    async def _processar_deliver(self, msg: dict):
        remetente    = msg["from"]
        peer_pub_hex = msg.get("pub_key")
        cert         = msg.get("cert", "")
        if not peer_pub_hex:
            return

        if cert and self.ca_pub_hex:
            try:
                cert_user, cert_pub = verificar_certificado(cert, self.ca_pub_hex)
                if cert_user != remetente or cert_pub != peer_pub_hex:
                    print(f"\n[SEGURANÇA] Certificado de '{remetente}' não coincide!")
                    print("> ", end="", flush=True)
                    return
            except ValueError as e:
                print(f"\n[SEGURANÇA] {e}")
                print("> ", end="", flush=True)
                return
        else:
            # Fallback TOFU
            if remetente in self.trusted_keys:
                if self.trusted_keys[remetente] != peer_pub_hex:
                    print(f"\n[SEGURANÇA] Chave de '{remetente}' MUDOU! Possível ataque.")
                    print("> ", end="", flush=True)
                    return
            else:
                self.trusted_keys[remetente] = peer_pub_hex
                print(f"\n[TOFU] Chave de '{remetente}' gravada.")
                self._guardar()

        if remetente not in self.sessions:
            peer_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
            shared = self.identity_priv.exchange(peer_pub)
            # Como estás a receber, is_initiator = False
            self.sessions[remetente] = iniciar_sessao_ratchet(
                self._username_atual, remetente, shared,
                self.identity_priv, peer_pub_hex, False)
        try:
            texto = self.sessions[remetente].decrypt(bytes.fromhex(msg["data"]))
            print(f"\n[CHAT] {remetente}: {texto}")
            self._guardar()
        except Exception as e:
            print(f"\n[ERRO] Falha ao desencriptar mensagem de '{remetente}': {e}")
        print("> ", end="", flush=True)

    async def _processar_group_deliver(self, msg: dict):
        group_id = msg.get("group_id")
        remetente = msg["from"]

        if group_id not in self.groups:
            return

        try:
            g_state = self.groups[group_id]
            raw = bytes.fromhex(msg["data"])
            nonce, seq_b, ct = raw[:12], raw[12:16], raw[16:]
            msg_seq = struct.unpack("!I", seq_b)[0]

            cache_key = f"{remetente}_{msg_seq}"

            # 1. Verificar se a chave desta mensagem já está na cache (chegou fora de ordem antes)
            if cache_key in g_state["skipped"]:
                msg_key = bytes.fromhex(g_state["skipped"].pop(cache_key))
            else:
                # 2. Se não está na cache, temos de avançar o Ratchet do remetente
                chain_remetente = bytes.fromhex(g_state["chains"][remetente])
                seq_atual = g_state["seqs"][remetente]

                if msg_seq <= seq_atual:
                    print(f"\n[GRUPO] Mensagem repetida ou antiga bloqueada de {remetente}.")
                    return

                # Fast-forward do ratchet (gerar e guardar chaves de mensagens que falharam/estão atrasadas)
                while seq_atual < msg_seq:
                    seq_atual += 1
                    chain_remetente, gerada_key = _kdf_ck(chain_remetente)
                    if seq_atual < msg_seq:
                        # Guarda as chaves saltadas na cache
                        g_state["skipped"][f"{remetente}_{seq_atual}"] = gerada_key.hex()
                    else:
                        # Esta é a chave da mensagem atual
                        msg_key = gerada_key

                # Gravar o novo estado da corrente do colega no disco
                g_state["chains"][remetente] = chain_remetente.hex()
                g_state["seqs"][remetente] = seq_atual

            self._guardar()

            # 3. Decifrar a mensagem com a chave correta
            aad = remetente.encode() + seq_b
            texto = AESGCM(msg_key).decrypt(nonce, ct, aad).decode()

            nome_grupo = g_state.get("name", group_id)
            print(f"\n[GRUPO:{nome_grupo}] {remetente}: {texto}")

        except Exception as e:
            print(f"\n[ERRO] Falha ao desencriptar mensagem de grupo: {e}")

        print("> ", end="", flush=True)

    async def _processar_group_invite(self, msg: dict):
        group_id  = msg["group_id"]
        nome      = msg["name"]
        membros   = msg["members"]
        key_share = msg.get("key_share", "")

        if not key_share or group_id in self.groups:
            return
        try:
            group_key = decifrar_chave_grupo(key_share, self.identity_priv)
            self._inicializar_estado_grupo(group_id, nome, membros, group_key)
            print(f"\n[SISTEMA] Foste adicionado ao grupo '{nome}'!")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[ERRO] Falha ao processar convite do grupo '{nome}': {e}")
            print("> ", end="", flush=True)

    # ------------------------------------------------------------------ #
    #  P2P                                                                 #
    # ------------------------------------------------------------------ #

    async def _processar_p2p_signal(self, msg: dict):
        remetente = msg["from"]
        data      = msg.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                return
        peer_uri = data.get("uri")
        p2p_secret = data.get("p2p_secret")  # Lê o segredo recebido

        # Agora exigimos o segredo para prosseguir
        if not peer_uri or not p2p_secret or remetente in self._p2p_peers:
            return

        try:
            p2p_ws = await websockets.connect(peer_uri)
            await p2p_ws.send(json.dumps({
                "action": "p2p_hello",
                "from": self._username_atual,
                "p2p_secret": p2p_secret
            }))
            self._p2p_peers[remetente] = p2p_ws
            asyncio.create_task(self._escutar_p2p(remetente, p2p_ws))
            print(f"\n[P2P] Ligado diretamente a '{remetente}'.")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[P2P] Falha ao ligar a '{remetente}': {e}")

    async def _escutar_p2p(self, peer: str, p2p_ws):
        try:
            async for raw in p2p_ws:
                msg = json.loads(raw)
                if msg.get("action") == "p2p_msg":
                    await self._processar_p2p_msg(peer, msg)
        except Exception:
            pass
        finally:
            self._p2p_peers.pop(peer, None)
            print(f"\n[P2P] Ligação com '{peer}' encerrada.")

    async def _processar_p2p_msg(self, peer: str, msg: dict):
        if peer not in self.sessions:
            print(f"\n[P2P] Sessão com '{peer}' não inicializada.")
            return
        try:
            texto = self.sessions[peer].decrypt(bytes.fromhex(msg["data"]))
            print(f"\n[P2P:{peer}] {texto}")
            self._guardar()
        except Exception as e:
            print(f"\n[P2P] Erro ao desencriptar: {e}")
        print("> ", end="", flush=True)

    async def iniciar_p2p_server(self, porta: int = 9000) -> int:
        """Inicia servidor WebSocket local para ligações P2P diretas."""

        async def p2p_handler(ws):
            peer = None
            try:
                raw = await ws.recv()
                msg = json.loads(raw)
                peer = msg.get("from")
                recebido_secret = msg.get("p2p_secret")

                # 1. Falta de dados
                if not peer or not recebido_secret:
                    await ws.close(1008, "Faltam credenciais")
                    return

                # 2. Autenticação estrita (compara os segredos de forma segura)
                esperado = self._expected_p2p_tokens.get(peer)
                if not esperado or not secrets.compare_digest(esperado, recebido_secret):
                    print(f"\n[SEGURANÇA] Tentativa de acesso P2P negada de '{peer}'.")
                    await ws.close(1008, "Token P2P inválido")
                    return

                # 3. Consumir o token (só pode ser usado uma vez)
                self._expected_p2p_tokens.pop(peer, None)

                # 4. Autorizado!
                if peer not in self._p2p_peers:
                    self._p2p_peers[peer] = ws
                    print(f"\n[P2P] '{peer}' ligou-se e autenticou-se diretamente.")
                    print("> ", end="", flush=True)
                if msg.get("action") == "p2p_msg":
                    await self._processar_p2p_msg(peer, msg)
                async for raw in ws:
                    msg = json.loads(raw)
                    await self._processar_p2p_msg(peer, msg)
            except Exception:
                pass
            finally:
                if peer:
                    self._p2p_peers.pop(peer, None)

        self._p2p_server = await websockets.serve(p2p_handler, "localhost", porta)
        print(f"[P2P] Servidor P2P local em ws://localhost:{porta}")
        return porta

    async def convidar_p2p(self, token: str, peer: str, porta: int) -> dict:
        # Gera um segredo aleatório de 32 caracteres (16 bytes hex)
        p2p_secret = secrets.token_hex(16)

        # Regista que estamos à espera deste segredo vindo deste peer
        self._expected_p2p_tokens[peer] = p2p_secret

        return await self._enviar({
            "action": "p2p_signal",
            "to": peer,
            "token": token,
            "data": {
                "uri": f"ws://localhost:{porta}",
                "p2p_secret": p2p_secret
            },
        })

    async def _enviar_p2p(self, peer: str, texto: str) -> dict:
        if peer not in self.sessions:
            return {"status": "error", "reason": "Sem sessão com este peer."}
        ct = self.sessions[peer].encrypt(texto)
        self._guardar()
        await self._p2p_peers[peer].send(json.dumps({
            "action": "p2p_msg", "data": ct.hex(),
        }))
        return {"status": "ok", "message": "Enviado via P2P."}

    # ------------------------------------------------------------------ #
    #  Registo e login                                                     #
    # ------------------------------------------------------------------ #

    async def registar(self, username: str, password: str) -> dict:
        if self._token is not None or self._username_atual is not None:
            return {"status": "error", "reason": "Já existe uma sessão ativa. Faça logout primeiro."}
        self.identity_priv    = X25519PrivateKey.generate()
        self.identity_pub_hex = self.identity_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

        salt      = os.urandom(16)
        base_hash = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(
            password.encode())

        payload          = {"salt": salt.hex(), "hash": base_hash.hex(),
                            "chat_pub_key": self.identity_pub_hex}
        pub, nonce, cifra = encriptar_payload(self.server_pub, payload)

        resp = await self._enviar({
            "action": "register", "username": username,
            "pub_key": pub, "nonce": nonce, "cifra": cifra,
        })
        if resp.get("status") == "ok":
            self.my_cert = resp.get("cert", "")
            guardar_estado_local(
                username, password, self.identity_priv,
                self.sessions, self.trusted_keys,
                self.my_cert, self.ca_pub_hex or "", self.groups)
        return resp

    async def login(self, username: str, password: str) -> dict:
        if self._token is not None or self._username_atual is not None:
            return {"status": "error", "reason": "Já existe uma sessão ativa. Faça logout primeiro."}
        resp_ch = await self._enviar({"action": "get_challenge", "username": username})
        if resp_ch.get("status") != "ok":
            return resp_ch

        challenge  = bytes.fromhex(resp_ch["challenge"])
        salt       = bytes.fromhex(resp_ch["salt"])
        base_hash  = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(
            password.encode())
        resp_hmac  = hmac.new(base_hash, challenge, hashlib.sha256).digest()

        pub, nonce, cifra = encriptar_payload(
            self.server_pub, {"response": resp_hmac.hex()})

        resp = await self._enviar({
            "action": "login", "username": username,
            "pub_key": pub, "nonce": nonce, "cifra": cifra,
        })

        if resp.get("status") == "ok":
            if resp.get("ca_pub"):
                self.ca_pub_hex = resp["ca_pub"]
            try:
                (self.identity_priv, self.sessions, self.trusted_keys,
                 self.my_cert, ca_local, self.groups) = \
                    carregar_estado_local(username, password)
                if ca_local and not self.ca_pub_hex:
                    self.ca_pub_hex = ca_local
            except ValueError as e:
                return {"status": "error", "reason": str(e)}

            self.identity_pub_hex = self.identity_priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            self._token           = resp["token"]
            self._username_atual  = username
            self._password_atual  = password

            if self._escuta_task is None:
                self._escuta_task = asyncio.create_task(self._escutar())
                print(f"[SISTEMA] Carregado: {len(self.sessions)} conversas, "
                      f"{len(self.groups)} grupos.")
                print("[CLIENTE] Modo de receção contínua activado.")
        return resp

    async def logout(self) -> dict:
        """Limpa todo o estado do cliente e termina processos em background."""
        if not self._token:
            return {"status": "error", "reason": "Nenhuma sessão ativa para fazer logout."}

        # 1. Cancelar o loop de escuta do servidor
        if self._escuta_task:
            self._escuta_task.cancel()
            self._escuta_task = None

        # 2. Fechar ligações diretas P2P que estejam abertas
        for peer, p2p_ws in self._p2p_peers.items():
            await p2p_ws.close()
        self._p2p_peers.clear()
        self._expected_p2p_tokens.clear()

        # 3. Aniquilar variáveis sensíveis em memória
        self._token = None
        self._username_atual = None
        self._password_atual = None
        self.identity_priv = None
        self.identity_pub_hex = None
        self.my_cert = ""
        self.sessions.clear()
        self.groups.clear()
        self.trusted_keys.clear()

        return {"status": "ok", "message": "Logout efetuado com sucesso. A sessão foi limpa da memória."}

    # ------------------------------------------------------------------ #
    #  Mensagens diretas                                                   #
    # ------------------------------------------------------------------ #

    async def enviar_msg(self, token: str, to: str, texto: str) -> dict:
        if to in self._p2p_peers:
            return await self._enviar_p2p(to, texto)

        resp = await self._enviar({"action": "get_key", "target": to, "token": token})
        if resp.get("status") != "ok":
            return resp

        peer_pub_hex = resp["pub_key"]
        cert         = resp.get("cert", "")

        if cert and self.ca_pub_hex:
            try:
                cert_user, cert_pub = verificar_certificado(cert, self.ca_pub_hex)
                if cert_user != to or cert_pub != peer_pub_hex:
                    return {"status": "error",
                            "reason": "Certificado não coincide com a chave!"}
            except ValueError as e:
                return {"status": "error", "reason": str(e)}
        else:
            if to in self.trusted_keys:
                if self.trusted_keys[to] != peer_pub_hex:
                    return {"status": "error",
                            "reason": f"Chave inválida para '{to}' (possível MITM)."}
            else:
                self.trusted_keys[to] = peer_pub_hex
                print(f"\n[TOFU] Chave de '{to}' gravada.")

        if to not in self.sessions:
            peer_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
            shared = self.identity_priv.exchange(peer_pub)
            # Como estás a enviar a primeira mensagem, is_initiator = True
            self.sessions[to] = iniciar_sessao_ratchet(
                self._username_atual, to, shared,
                self.identity_priv, peer_pub_hex, True)

        ct = self.sessions[to].encrypt(texto)
        self._guardar()
        return await self._enviar({
            "action": "msg", "to": to,
            "data":   ct.hex(), "token": token,
        })

    # ------------------------------------------------------------------ #
    #  Grupos                                                            #
    # ------------------------------------------------------------------ #

    def _get_group_id_by_name(self, name: str) -> str | None:
        for gid, info in self.groups.items():
            if info["name"].lower() == name.lower():
                return gid
        return None

    def _inicializar_estado_grupo(self, group_id: str, nome: str, membros: list, group_key: bytes):
        chains = {}
        for m in membros:
            chain = HKDF(hashes.SHA256(), 32, None, m.encode()).derive(group_key)
            chains[m] = chain.hex()

        self.groups[group_id] = {
            "name": nome,
            "members": membros,
            "chains": chains,  # Estado atual da corrente de cada um
            "seqs": {m: 0 for m in membros},  # Número de sequência atual de cada um
            "skipped": {}  # Cache de chaves do futuro (mensagens fora de ordem)
        }
        self._guardar()

    async def criar_grupo(self, token: str, nome: str, membros: list) -> dict:
        group_key  = os.urandom(32)
        key_shares = {}
        todos      = list(set([self._username_atual] + membros))

        for membro in todos:
            if membro == self._username_atual:
                pub_hex = self.identity_pub_hex
            else:
                resp = await self._enviar(
                    {"action": "get_key", "target": membro, "token": token})
                if resp.get("status") != "ok":
                    return {"status": "error",
                            "reason": f"Falha ao obter chave de '{membro}'."}
                pub_hex = resp["pub_key"]
            key_shares[membro] = cifrar_chave_grupo(group_key, pub_hex)

        resp = await self._enviar({
            "action":     "create_group",
            "name":       nome,
            "members":    todos,
            "key_shares": key_shares,
            "token":      token,
        })
        if resp.get("status") == "ok":
            if resp.get("status") == "ok":
                group_id = resp["group_id"]
                self._inicializar_estado_grupo(group_id, nome, todos, group_key)
        return resp

    async def enviar_grupo(self, token: str, group_id: str, texto: str) -> dict:
        if group_id not in self.groups:
            return {"status": "error", "reason": "Grupo não encontrado."}

        # 1. Recuperar o estado da MINHA corrente
        my_user = self._username_atual
        minha_chain = bytes.fromhex(self.groups[group_id]["chains"][my_user])
        meu_seq = self.groups[group_id]["seqs"][my_user] + 1

        # 2. Avançar o ratchet simétrico para gerar a chave efémera da mensagem
        nova_chain, msg_key = _kdf_ck(minha_chain)

        # 3. Atualizar o estado local (para a próxima mensagem usar a nova corrente)
        self.groups[group_id]["chains"][my_user] = nova_chain.hex()
        self.groups[group_id]["seqs"][my_user] = meu_seq
        self._guardar()

        # 4. Cifrar
        nonce = os.urandom(12)
        seq_b = struct.pack("!I", meu_seq)

        aad = my_user.encode() + seq_b
        ct = AESGCM(msg_key).encrypt(nonce, texto.encode(), aad)

        return await self._enviar({
            "action": "group_msg",
            "group_id": group_id,
            "data": (nonce + seq_b + ct).hex(),
            "token": token,
        })

    # ------------------------------------------------------------------ #
    #  Auxiliares internos                                                 #
    # ------------------------------------------------------------------ #

    def _guardar(self):
        guardar_estado_local(
            self._username_atual, self._password_atual,
            self.identity_priv, self.sessions, self.trusted_keys,
            self.my_cert, self.ca_pub_hex or "", self.groups)

    async def _enviar(self, msg: dict) -> dict:
        if self._escuta_task is not None:
            async with self._send_lock:
                loop             = asyncio.get_event_loop()
                self._cmd_future = loop.create_future()
                await self.ws.send(json.dumps(msg))
                resposta         = await self._cmd_future
                self._cmd_future = None
                return resposta
        else:
            await self.ws.send(json.dumps(msg))
            return json.loads(await self.ws.recv())