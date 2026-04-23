"""
client/cli.py
-------------
Interface de linha de comandos (CLI) do cliente de chat E2EE.

Este módulo trata exclusivamente da interação com o utilizador:
parsing de comandos, apresentação de resultados e chamadas à ClienteWS.
Toda a lógica de rede e criptografia está em ws_client.py.
"""

import asyncio
import getpass

from client.ws_client import ClienteWS


AJUDA = """
Comandos disponíveis:
  register <user>                  -- registar nova conta
  login <user>                     -- autenticar
  logout <user>                    -- logout
  msg <dest> <texto>               -- enviar mensagem direta
  list                             -- listar conversas ativas
  group create <nome> <m1> [m2]..  -- criar grupo com membros
  group list                       -- listar os teus grupos
  group msg <nome_grupo> <texto>   -- enviar mensagem ao grupo
  p2p start [porta]                -- iniciar servidor P2P local (default 9000)
  p2p invite <peer> [porta]        -- convidar peer para ligação P2P direta
  ajuda                            -- mostrar esta ajuda
  sair
"""


async def main():
    print(AJUDA)

    async with ClienteWS() as c:
        token = None

        while True:
            try:
                linha = await asyncio.get_event_loop().run_in_executor(
                    None, input, "> ")
            except EOFError:
                break

            partes = linha.strip().split()
            if not partes:
                continue
            cmd = partes[0].lower()

            # ---- sair ------------------------------------------------- #
            if cmd == "sair":
                break

            # ---- register --------------------------------------------- #
            if token is None:
                if cmd == "register" and len(partes) == 2:
                    pw = await asyncio.get_event_loop().run_in_executor(
                        None, getpass.getpass, "Password: ")
                    r = await c.registar(partes[1], pw)
                    print(r)

            # ---- login ------------------------------------------------ #
                elif cmd == "login" and len(partes) == 2:
                    pw = await asyncio.get_event_loop().run_in_executor(
                        None, getpass.getpass, "Password: ")
                    r = await c.login(partes[1], pw)
                    print(r)
                    if r.get("status") == "ok":
                        token = r["token"]
                else:
                    print("[ERRO] Comando não reconhecido ou precisa de estar autenticado.")
                    print("Tente /login ou /register")
            else:

                if cmd == "login" or cmd == "register":
                    print("[ERRO] Já tem uma sessão ativa. Escreva /logout primeiro.")

                elif cmd == "logout":
                    resposta = await c.logout()
                    token = None
                    print(f"[SISTEMA] {resposta['message']}")
                elif cmd == "msg" and len(partes) >= 3:
                    if not token:
                        print("[CLIENTE] Faça login primeiro.")
                        continue
                    texto = " ".join(partes[2:])
                    r = await c.enviar_msg(token, partes[1], texto)
                    if r.get("status") == "error":
                        print(f"[ERRO] {r.get('reason')}")

                # ---- list ------------------------------------------------- #
                elif cmd == "list":
                    if not token:
                        print("[CLIENTE] Faça login primeiro.")
                        continue
                    if not c.sessions:
                        print("[LISTA] Ainda não trocaste mensagens com ninguém.")
                    else:
                        print(f"[LISTA] Conversas ({len(c.sessions)}): "
                              f"{', '.join(c.sessions.keys())}")

                # ---- group ------------------------------------------------ #
                elif cmd == "group" and len(partes) >= 2:
                    if not token:
                        print("[CLIENTE] Faça login primeiro.")
                        continue
                    sub = partes[1].lower()

                    if sub == "create" and len(partes) >= 4:
                        nome    = partes[2]
                        membros = partes[3:]
                        r = await c.criar_grupo(token, nome, membros)
                        if r.get("status") == "ok":
                            print(f"[GRUPO] Grupo '{nome}' criado com sucesso!")
                        else:
                            print(f"[ERRO] {r.get('reason')}")

                    elif sub == "list":
                        if not c.groups:
                            print("[LISTA] Não pertences a nenhum grupo.")
                        else:
                            print("[LISTA] Os teus grupos:")
                            for gid, info in c.groups.items():
                                membros_str = ", ".join(info["members"])
                                print(f"  - {info['name']} "
                                      f"({len(info['members'])} membros: {membros_str})")

                    elif sub == "msg" and len(partes) >= 4:
                        nome_grupo = partes[2]
                        texto      = " ".join(partes[3:])
                        group_id   = c._get_group_id_by_name(nome_grupo)
                        if not group_id:
                            print(f"[ERRO] Não conheces nenhum grupo chamado '{nome_grupo}'.")
                        else:
                            r = await c.enviar_grupo(token, group_id, texto)
                            if r.get("status") == "error":
                                print(f"[ERRO] {r.get('reason')}")

                    else:
                        print("Uso: group create <nome> <m1> [m2] | "
                              "group list | group msg <nome> <texto>")

                # ---- p2p -------------------------------------------------- #
                elif cmd == "p2p" and len(partes) >= 2:
                    if not token:
                        print("[CLIENTE] Faça login primeiro.")
                        continue
                    sub = partes[1].lower()

                    if sub == "start":
                        porta = int(partes[2]) if len(partes) >= 3 else 9000
                        await c.iniciar_p2p_server(porta)

                    elif sub == "invite" and len(partes) >= 3:
                        peer  = partes[2]
                        porta = int(partes[3]) if len(partes) >= 4 else 9000
                        r     = await c.convidar_p2p(token, peer, porta)
                        if r.get("status") == "ok":
                            print(f"[P2P] Convite enviado a '{peer}'.")
                        else:
                            print(f"[ERRO] {r.get('reason')}")
                    else:
                        print("Uso: p2p start [porta] | p2p invite <peer> [porta]")

                # ---- ajuda ------------------------------------------------ #
                elif cmd == "ajuda":
                    print(AJUDA)

                else:
                    print("Comando não reconhecido. Escreve 'ajuda' para ver os comandos.")


if __name__ == "__main__":
    asyncio.run(main())