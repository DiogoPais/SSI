# Relatório — Sistema de Chat com End-to-End Encryption (E2EE)

> **Projeto de Segurança de Sistemas Informáticos**

---

## Índice

1. [Arquitetura da Solução](#1-arquitetura-da-solução)
2. [Fluxos de Comunicação](#2-fluxos-de-comunicação)
3. [Funcionalidades Implementadas](#3-funcionalidades-implementadas)
4. [Modelo de Segurança](#4-modelo-de-segurança)
5. [Limitações Conhecidas](#5-limitações-conhecidas)
6. [Melhorias Não Implementadas](#6-melhorias-não-implementadas)

---

## 1. Arquitetura da Solução

### 1.1 Visão Geral

O sistema segue uma arquitetura **cliente-servidor assimétrica**, onde o servidor atua como ponto central de coordenação e relay, sem nunca ter acesso ao conteúdo das mensagens. Toda a lógica criptográfica reside exclusivamente nos clientes.

```
Cliente A                    Servidor (relay)                  Cliente B
   |                               |                               |
   |── WebSocket TLS ─────────────>|<──────────── WebSocket TLS ───|
   |                               |                               |
   |   mensagem cifrada (E2EE)     |     mensagem cifrada (E2EE)   |
   |──────────────────────────────>|──────────────────────────────>|
   |                               |                               |
```

O servidor é considerado **honesto-mas-curioso**: executa corretamente o protocolo, mas não tem acesso ao conteúdo das mensagens.

### 1.2 Estrutura do Código

O projeto está organizado em três módulos principais:

| Módulo | Ficheiros | Responsabilidade |
|---|---|---|
| `common/` | `crypto.py`, `pki.py`, `protocol.py`, `ratchet.py` | Primitivas criptográficas partilhadas entre cliente e servidor |
| `server/` | `servidor.py`, `auth.py`, `handlers.py`, `persistence.py` | Lógica do servidor WebSocket |
| `client/` | `ws_client.py`, `crypto.py`, `Cliente.py` | Lógica de rede, criptografia e interface do cliente |

### 1.3 Servidor

O servidor (`servidor.py`) é responsável por:

- Gerir o registo e autenticação de utilizadores.
- Atuar como **Autoridade de Certificação (CA)**, emitindo certificados Ed25519 a cada utilizador no momento do registo.
- Encaminhar mensagens cifradas entre clientes (online ou offline).
- Gerir grupos e distribuir as respetivas key shares cifradas.
- Servir de canal de sinalização para ligações P2P diretas.
- Persistir o estado de forma cifrada em disco (`estado_servidor.bin`).

O servidor escuta ligações WebSocket sobre TLS na porta `8765` (`wss://localhost:8765`).

### 1.4 Cliente

O cliente está dividido em duas camadas:

- **`ws_client.py` (ClienteWS):** toda a lógica de rede, criptografia e gestão de sessões Double Ratchet. Gere o estado local de cada sessão E2EE e comunica com o servidor através de WebSocket sobre TLS.
- **`Cliente.py` (CLI):** interface de linha de comandos. Faz parsing dos comandos do utilizador e delega para a `ClienteWS`.

O estado do cliente (chaves privadas, sessões ratchet, grupos) é persistido localmente em `estado_<username>.bin`, cifrado com AES-256-GCM com chave derivada da password do utilizador via PBKDF2.

### 1.5 Gestão de Chaves

Cada utilizador possui **dois pares de chaves distintos com propósitos separados**:

- **Chave de identidade X25519** (`identity_priv`): chave estática de longa duração usada exclusivamente para o Double Ratchet e para decifrar key shares de grupo.
- **Chave de autenticação Ed25519** (`auth_priv`): chave usada exclusivamente para assinar o desafio de login. A chave pública correspondente é registada no servidor como âncora de identidade, substituindo completamente o modelo anterior baseado em hash de password.
- **Certificado Ed25519** emitido pela CA do servidor no momento do registo, que associa o `username` à chave pública X25519 de chat.

O servidor mantém:

- **Chave X25519 de transporte**: usada para cifrar os payloads de registo/login enviados pelo cliente (ECDH efémero + AES-GCM).
- **Chave privada Ed25519 da CA**: usada para assinar certificados de utilizadores.
- **Segredo JWT**: usado para emitir e verificar tokens de sessão.
- **`auth_pub_key` por utilizador**: único material de autenticação armazenado — o servidor nunca guarda qualquer derivado de password.

---

## 2. Fluxos de Comunicação

### 2.1 Handshake TLS e Verificação da CA

Ao ligar-se, o cliente:

1. Estabelece uma ligação WebSocket com TLS, verificando o certificado TLS do servidor via `ssl.SSLContext`.
2. Recebe um `server_hello` com a chave pública X25519 do servidor, a chave pública da CA e uma assinatura Ed25519 da chave do servidor feita pela CA.
3. Compara a CA recebida com a CA previamente gravada em `ca_pinned.pub` (CA pinning). Se não coincidir, rejeita a ligação imediatamente como possível ataque MITM.
4. Verifica a assinatura Ed25519 sobre a chave pública do servidor. Se inválida, a ligação é encerrada.

Só após estas duas verificações o cliente considera a ligação segura e prossegue.

### 2.2 Registo

1. O cliente gera dois pares de chaves localmente: um par X25519 para chat (`identity_priv`) e um par Ed25519 para autenticação (`auth_priv`).
2. Constrói o payload `{auth_pub_key, chat_pub_key}` e cifra-o com ECDH efémero + AES-GCM usando a chave pública X25519 do servidor.
3. O servidor decifra, valida que `auth_pub_key` é uma chave Ed25519 bem formada, regista o utilizador e emite um certificado Ed25519 associando o `username` à `chat_pub_key`.
4. O servidor nunca recebe nem armazena qualquer derivado de password — apenas as duas chaves públicas.
5. O certificado é devolvido ao cliente e guardado no estado local cifrado juntamente com as chaves privadas.

### 2.3 Login (Challenge-Response com Ed25519)

O login segue um protocolo de challenge-response em dois passos:

1. **`get_challenge`:** o cliente pede um desafio. O servidor gera 32 bytes aleatórios e devolve-os. Ao contrário da versão anterior, não é devolvido nenhum `salt` (que deixou de existir na base de dados do servidor).
2. **`login`:** o cliente carrega a sua chave privada Ed25519 do disco (o que valida a password localmente via PBKDF2, pois o estado está cifrado com ela), assina o desafio com `auth_priv.sign(challenge)`, cifra a assinatura com ECDH efémero e envia ao servidor. O servidor verifica a assinatura com a `auth_pub_key` registada e, se válida, emite um JWT com validade de 2 horas.

Este esquema garante que **o servidor nunca tem acesso a qualquer segredo do utilizador** — mesmo um servidor completamente comprometido não consegue fazer impersonation, pois nunca teve contacto com a chave privada Ed25519.

### 2.4 Envio de Mensagem Direta

1. O remetente obtém a chave pública X25519 e o certificado Ed25519 do destinatário junto do servidor (`get_key`).
2. Verifica o certificado com a CA local. Se o certificado estiver ausente ou inválido, a operação é **rejeitada sem qualquer fallback** — o sistema não usa TOFU.
3. Se for a primeira mensagem entre os dois peers, inicia uma sessão Double Ratchet. O iniciador gera internamente um par X25519 **efémero** para o primeiro passo DH — nunca usa as suas chaves estáticas diretamente.
4. Cifra o texto com o Double Ratchet (AES-256-GCM com message key derivada pelo ratchet simétrico).
5. Envia o payload cifrado ao servidor, que o encaminha para o destinatário (online) ou guarda na fila offline.

### 2.5 Receção de Mensagem

O cliente corre um loop de escuta contínuo (`_escutar`) que processa mensagens push do servidor. Ao receber uma mensagem:

1. Verifica a presença e validade do certificado Ed25519 do remetente. Se ausente ou inválido, a mensagem é **descartada** — sem TOFU, sem fallback.
2. Se não houver sessão com este peer, inicializa-a como recetor (`is_initiator=False`). O primeiro DH ratchet é executado quando a primeira mensagem chegar, usando a chave efémera do iniciador contida no payload.
3. Decifra com o Double Ratchet, avançando o ratchet simétrico.

Após login bem-sucedido, o cliente envia uma mensagem `ready` ao servidor, que entrega então as mensagens offline pendentes.

### 2.6 Mensagens de Grupo

**Criação:**
1. O criador gera uma `group_key` aleatória de 32 bytes.
2. Para cada membro, obtém a chave pública X25519 e **valida o certificado PKI** obrigatoriamente — sem certificado válido, o membro não é adicionado.
3. Para cada membro, cifra a `group_key` com ECDH **efémero one-shot** + AES-GCM usando `cifrar_chave_grupo()`. Um par efémero diferente é gerado e descartado para cada membro.
4. Envia ao servidor o grupo com todas as key shares cifradas.
5. O servidor notifica cada membro online, ou guarda o convite na fila offline.

**Receção de convite:** O membro recebe a sua key share e decifra-a com `decifrar_chave_grupo()`, reconstruindo o shared secret via `our_static_priv × eph_pub`. Não é necessária qualquer sessão Ratchet prévia com o criador.

**Envio de mensagem de grupo:**
1. O remetente avança o seu ratchet simétrico pessoal dentro do grupo (chain derivada com HKDF a partir da `group_key` e do seu `username`).
2. Cifra o texto com AES-256-GCM, usando `username + número de sequência` como AAD.
3. O servidor distribui o payload cifrado a todos os membros.

**Receção de mensagem de grupo:** O recetor avança o ratchet simétrico do remetente até ao número de sequência correto, guardando chaves intermédias para mensagens fora de ordem, e decifra com AES-GCM verificando o AAD.

### 2.7 Modo P2P Direto

1. O cliente que inicia (`p2p start`) arranca um servidor WebSocket local na porta indicada.
2. Gera um token aleatório (`p2p_secret`) e envia ao peer um convite via servidor (`p2p_signal`), com o endereço e o token.
3. O peer recebe o sinal, liga-se diretamente ao servidor P2P e autentica-se com o token usando `secrets.compare_digest` (resistente a timing attacks).
4. As mensagens seguintes passam diretamente entre os dois clientes, sem passar pelo servidor, usando o Double Ratchet da sessão já existente.

### 2.8 Logout

O logout notifica o servidor, cancela o loop de escuta, fecha todas as ligações P2P abertas e **limpa ativamente todas as variáveis sensíveis da memória** (`identity_priv`, `auth_priv`, `sessions`, `groups`, `trusted_keys`, token), evitando que o estado criptográfico fique acessível após a sessão terminar.

---

## 3. Funcionalidades Implementadas

### 3.1 Funcionalidades Base

- **Registo de utilizadores** com geração de par Ed25519 de autenticação e X25519 de chat.
- **Login challenge-response** com assinatura Ed25519 e emissão de JWT.
- **Mensagens diretas E2EE** com Double Ratchet.
- **Interface de linha de comandos (CLI)** com comandos textuais.
- **Logout** com notificação ao servidor e limpeza completa do estado sensível em memória.

### 3.2 Valorizações Implementadas

#### Mensagens Offline
O servidor guarda as mensagens (já cifradas, sem acesso ao conteúdo) na `offline_queue` quando o destinatário não está ligado. Quando o utilizador faz login e envia a mensagem `ready`, todas as mensagens pendentes são entregues imediatamente. O mesmo mecanismo aplica-se a convites de grupo.

#### Entidade de Certificação (PKI) sem TOFU
O servidor atua como CA self-signed com uma chave Ed25519 própria. No momento do registo, emite um certificado no formato:
```
payload = "username|chat_pub_hex|timestamp"
certificado = payload_hex + "." + assinatura_Ed25519_hex
```
O cliente verifica este certificado antes de iniciar qualquer sessão ou aceitar qualquer mensagem. Não existe qualquer fallback TOFU — ausência ou invalidade de certificado resulta em rejeição imediata. O cliente usa CA pinning: compara a CA recebida do servidor com a gravada localmente em `ca_pinned.pub`, detetando qualquer tentativa de substituição.

#### Modo Descentralizado P2P
Os clientes podem estabelecer ligações WebSocket diretas entre si, dispensando o servidor como relay. O servidor funciona apenas como canal de sinalização para a troca inicial de endereços e token de autenticação P2P. As mensagens P2P continuam a usar o Double Ratchet da sessão existente.

#### Mensagens de Grupo com Forward Secrecy
Grupos com múltiplos membros, com distribuição de chave de grupo via ECDH efémero one-shot por membro. Cada membro tem o seu próprio ratchet simétrico dentro do grupo, com números de sequência e proteção contra replay. A validação PKI é obrigatória para todos os membros.

#### Forward Secrecy Total (Double Ratchet com handshake efémero)
O protocolo Double Ratchet garante forward secrecy a dois níveis:
- **Ratchet simétrico:** cada mensagem usa uma message key diferente, descartada após uso.
- **Ratchet DH:** a cada nova ronda de envio, gera-se um novo par X25519 efémero. O primeiro passo DH do handshake usa também um par efémero gerado no momento — nunca as chaves estáticas de identidade diretamente.

---

## 4. Modelo de Segurança

### 4.1 Primitivas Criptográficas

| Primitiva | Algoritmo | Utilização |
|---|---|---|
| Troca de chaves | X25519 (ECDH) | Handshake Double Ratchet; cifragem de payloads de autenticação; key shares de grupo |
| Cifragem simétrica | AES-256-GCM | Cifragem de mensagens, payloads de autenticação e estado local |
| Derivação de chave | HKDF-SHA256 | Derivação de root key, chain key, message key, chave de transporte e chains de grupo |
| Proteção do estado local | PBKDF2-SHA256 (600 000 iterações) | Derivação da KEK para cifrar/decifrar o estado local do cliente e do servidor |
| Assinatura digital (CA e certificados) | Ed25519 | Certificados de utilizador emitidos pela CA; assinatura da chave do servidor no `server_hello` |
| Assinatura digital (autenticação) | Ed25519 | Prova de posse da identidade no login (challenge-response) |
| Autenticação de sessão | JWT (HS256) | Tokens de sessão para operações autenticadas após login |
| Autenticação de mensagem | AES-GCM (AAD) | Header do ratchet (chave DH + sequência) e identidade do remetente em grupos |

### 4.2 Justificação e Comparação das Primitivas Escolhidas

#### X25519 vs. RSA, P-256, FFDH

Para a troca de chaves foi escolhido **X25519 (ECDH sobre Curve25519)**. O RSA foi descartado porque não oferece forward secrecy de forma nativa — se a chave privada for comprometida, todo o histórico de comunicações pode ser decifrado retroativamente — e porque as chaves RSA são ordens de magnitude maiores (2048–4096 bits vs. 32 bytes do X25519).

O FFDH clássico tem os mesmos problemas de dimensão de chave e é vulnerável a ataques de Logjam quando grupos estandardizados são reutilizados entre implementações.

O P-256 seria uma alternativa razoável, mas a Curve25519 é resistente a ataques de timing por design (sem operações condicionais sobre segredos), os seus parâmetros foram gerados de forma transparente e verificável — ao contrário dos parâmetros NIST do P-256, que levantam dúvidas históricas sobre possível backdoor — e a performance é superior. É a escolha padrão em protocolos modernos como TLS 1.3, Signal e WireGuard.

#### AES-256-GCM vs. AES-CBC, ChaCha20-Poly1305, AES-CTR

Para cifragem simétrica foi escolhido **AES-256-GCM**. O AES-CBC com HMAC separado é uma fonte histórica de vulnerabilidades graves como ataques BEAST e ataques de padding oracle, pois exige implementar corretamente o esquema MAC-then-Encrypt vs. Encrypt-then-MAC. O AES-GCM integra autenticação e cifragem numa só operação (AEAD), eliminando esta classe de erros e garantindo autenticidade do ciphertext e do AAD simultaneamente. O AES-CTR sem autenticação foi excluído por não oferecer integridade nem autenticidade.

O ChaCha20-Poly1305 seria uma alternativa moderna igualmente válida, com vantagem em hardware sem instruções AES-NI. No entanto, o AES-256-GCM beneficia de aceleração por hardware (via AES-NI) em praticamente todos os processadores modernos, tornando-os equivalentes na prática, e o suporte na biblioteca `cryptography` do Python é igualmente maduro.

#### HKDF-SHA256 vs. uso direto do output ECDH

O **HKDF** é o padrão recomendado pelo NIST (RFC 5869) para derivação de chaves a partir de shared secrets ECDH. Usar o output X25519 diretamente como chave AES seria incorreto: o output do ECDH não está uniformemente distribuído no espaço de chaves AES e pode ter estrutura explorável. O HKDF aplica extração (HMAC-SHA256 com salt) seguida de expansão, produzindo bytes pseudoaleatórios de alta qualidade.

#### PBKDF2-SHA256 (600 000 iterações) vs. bcrypt, scrypt, Argon2id

Para proteger o estado local cifrado foi escolhido **PBKDF2-SHA256 com 600 000 iterações** (valor recomendado pelo OWASP em 2023 para PBKDF2-SHA256). Um hash simples como SHA-256 foi excluído imediatamente: sem custo computacional deliberado, um atacante com GPU pode testar biliões de passwords por segundo. O bcrypt tem um limite de 72 caracteres e não permite configurar o custo de memória. O scrypt e o Argon2id são superiores em resistência a hardware especializado graças ao seu parâmetro de custo de memória — seriam escolhas ideais num sistema de produção. O PBKDF2 foi mantido porque está disponível nativamente na biblioteca `cryptography` do Python sem dependências adicionais, e com 600 000 iterações oferece proteção adequada neste contexto. O salt aleatório de 16 bytes por utilizador garante que dois utilizadores com a mesma password produzem ciphertexts diferentes, eliminando ataques de rainbow table.

#### Ed25519 vs. RSA-PSS, ECDSA P-256

Para assinaturas digitais (certificados CA, autenticação do servidor e login dos clientes) foi escolhido **Ed25519**. O RSA-PSS tem problemas de dimensão de chave e performance. O ECDSA sobre P-256 tem um problema crítico: a sua segurança depende da qualidade do gerador de números aleatórios no momento da assinatura — se o nonce for previsível ou reutilizado, a chave privada pode ser recuperada. Esta vulnerabilidade foi explorada em vários ataques reais, incluindo na Sony PlayStation 3. O Ed25519 é determinístico (EdDSA): o nonce é derivado deterministicamente da chave privada e da mensagem, eliminando completamente este risco. Oferece ainda chaves de 32 bytes, assinaturas de 64 bytes, verificação muito rápida e resistência a ataques de timing por design.

#### Double Ratchet vs. TLS puro, PGP, cifra estática de sessão

O **Double Ratchet** é a escolha central deste sistema. Uma cifra de sessão estática seria catastrófica: se a chave for descoberta, todas as mensagens passadas e futuras ficam expostas. O PGP cifra com a chave pública do destinatário diretamente, sem forward secrecy — o histórico fica exposto se a chave privada for comprometida. O TLS oferece forward secrecy ao nível da sessão de transporte, mas não ao nível das mensagens individuais dentro de uma sessão.

O Double Ratchet combina um **ratchet DH** (que roda as chaves de sessão a cada nova ronda, garantindo break-in recovery) com um **ratchet simétrico** (que gera uma chave única por mensagem, garantindo forward secrecy intra-sessão). Esta combinação fornece simultaneamente forward secrecy e break-in recovery — propriedades que nenhuma das alternativas acima oferece de forma completa. É exatamente o protocolo usado pelo Signal e WhatsApp.

#### Ed25519 para autenticação vs. HMAC-SHA256 com hash de password (versão anterior)

A versão anterior usava HMAC-SHA256 sobre um hash PBKDF2 da password como resposta ao desafio de login. Este esquema obrigava o servidor a armazenar um derivado da password (`salt` + `hash`), criando um vetor de ataque: um servidor comprometido poderia tentar ataques de dicionário offline sobre os hashes armazenados, ou usar o hash diretamente para autenticar (ataque pass-the-hash).

O esquema atual baseado em Ed25519 elimina este risco estruturalmente: o servidor armazena apenas a chave pública Ed25519, que é matematicamente inútil para autenticar — só quem possui a chave privada consegue produzir uma assinatura válida. Mesmo um servidor completamente comprometido não consegue fazer impersonation de utilizadores, pois nunca teve acesso ao segredo de autenticação.

### 4.3 Garantias de Segurança

**Confidencialidade:** As mensagens são cifradas ponta-a-ponta com AES-256-GCM. O servidor recebe apenas texto cifrado e nunca tem acesso às chaves de sessão, que são derivadas localmente nos clientes via ECDH efémero.

**Integridade:** O AES-GCM inclui um MAC de 128 bits que autentica simultaneamente o ciphertext e o header (chave pública DH + número de sequência). Qualquer adulteração invalida o MAC e a mensagem é rejeitada.

**Autenticidade de utilizadores:** Os certificados Ed25519 emitidos pela CA garantem a ligação entre um `username` e a respetiva chave pública X25519. O cliente verifica sempre o certificado antes de iniciar uma sessão ou aceitar uma mensagem. Não existe qualquer fallback TOFU — sem certificado válido, a operação falha.

**Autenticação sem exposição de segredos:** O login usa assinatura Ed25519 sobre um desafio aleatório. O servidor armazena apenas a chave pública Ed25519 de cada utilizador — nunca derivados de password. Um servidor comprometido não consegue fazer impersonation.

**Proteção contra MITM:** O CA pinning impede que um atacante no canal substitua a CA por uma sua. A assinatura Ed25519 da chave de transporte do servidor feita pela CA garante que o cliente está a falar com o servidor legítimo.

**Forward Secrecy:** O Double Ratchet garante que comprometer uma chave de sessão não compromete mensagens passadas. As message keys são descartadas após uso, os pares DH efémeros são descartados após cada ronda, e o handshake inicial usa também um par efémero — nunca static-static.

**Break-in Recovery:** Assim que o ratchet DH roda (nova chave efémera), um atacante que tenha obtido a chain key anterior perde acesso às mensagens seguintes.

**Proteção contra Replay:** O número de sequência é verificado em cada mensagem. Mensagens com sequência menor ou igual à última recebida são rejeitadas. Mensagens fora de ordem são tratadas com uma cache limitada a `MAX_SKIP=100` entradas, prevenindo ataques de exaustão de memória.

**Confidencialidade do estado local:** O estado de cada cliente é cifrado em disco com AES-256-GCM com chave derivada da password via PBKDF2, salt aleatório de 16 bytes e 600 000 iterações. O ficheiro tem permissões `0o600`.

**Cifragem do estado do servidor:** O servidor cifra a sua base de dados completa com AES-256-GCM e PBKDF2, protegendo os dados mesmo em caso de acesso físico ao disco.

**Autenticidade nas mensagens de grupo:** O `username` do remetente e o número de sequência são usados como AAD no AES-GCM, impedindo que um membro se faça passar por outro ou reutilize mensagens antigas.

**Forward Secrecy nas chaves de grupo:** A `group_key` é cifrada para cada membro com ECDH efémero one-shot. Comprometer a chave estática de um membro no futuro não expõe `group_keys` de grupos entretanto renovados ou destruídos, pois o par efémero já não existe.

### 4.4 Modelo de Ameaça

O sistema foi desenhado para resistir a:

- **Servidor curioso:** não tem acesso ao conteúdo das mensagens, às chaves privadas dos clientes, nem às chaves de grupo. Mesmo comprometido, não consegue fazer impersonation dos utilizadores.
- **Atacante na rede (MITM passivo):** toda a comunicação é cifrada com TLS e com E2EE.
- **Atacante na rede (MITM ativo):** o CA pinning e a verificação de certificados Ed25519 impedem a substituição de chaves.
- **Comprometimento de chave de sessão:** o Double Ratchet limita o impacto (break-in recovery).
- **Comprometimento de chave estática de longa duração:** o handshake efémero garante que mensagens passadas permanecem protegidas (forward secrecy).
- **Replay attacks:** números de sequência e descarte de message keys após uso.
- **Pass-the-hash / ataques offline à BD do servidor:** o servidor armazena apenas chaves públicas Ed25519, matematicamente inúteis para autenticar.

---

## 5. Limitações Conhecidas

**Sem renovação de chaves de longa duração:** As chaves de identidade X25519 e Ed25519 de cada utilizador são geradas no registo e mantidas indefinidamente. Não existe mecanismo de rotação ou revogação de chaves comprometidas.

**CA única centralizada:** O servidor é simultaneamente relay e CA. Um servidor comprometido poderia emitir certificados falsos para utilizadores legítimos. Num sistema de produção seria desejável uma CA separada ou um modelo de confiança distribuído.

**Handshake inicial sem prekeys:** O primeiro passo DH usa a chave estática X25519 do destinatário (combinada com um par efémero do iniciador). Se a chave estática do destinatário for comprometida, um atacante que tenha gravado o tráfego pode derivar o shared secret inicial. O protocolo X3DH do Signal resolve este problema através de prekeys publicadas.

**JWT sem revogação:** Os tokens JWT têm validade de 2 horas e não existem listas de revogação. Um token válido furtado mantém acesso até expirar.

**Sem anonimato de metadados:** O servidor conhece os padrões de comunicação: quem envia mensagens a quem, quando e com que frequência, mesmo sem ver o conteúdo.

**Chave de grupo estática sem mecanismo de exclusão:** A `group_key` de cada grupo não é renovada quando membros saem. Não existe mecanismo de exclusão de membros com rotação de chave.

**Sem proteção contra Denial of Service:** Não há rate limiting ou mecanismos de proteção contra abuso do servidor.

---

## 6. Melhorias Não Implementadas

**Extended Triple Diffie-Hellman (X3DH):** O protocolo Signal usa X3DH para o handshake inicial, que inclui chaves efémeras pré-publicadas (*prekeys*) pelo destinatário. Isto garantiria forward secrecy mesmo para a primeira mensagem, sem depender da chave estática do destinatário para o shared secret inicial.

**Argon2id para proteção de estado local:** A substituição do PBKDF2 por Argon2id aumentaria a resistência a ataques com hardware especializado (FPGAs, ASICs) graças ao parâmetro de custo de memória.

**Rotação e revogação de certificados:** Implementar um mecanismo de revogação de certificados e de renovação de chaves de identidade aumentaria a resiliência a comprometimento de chave a longo prazo.

**Exclusão dinâmica de membros de grupo:** Com rotação de `group_key` ao remover um membro, seria possível garantir que membros excluídos não acedem a mensagens futuras (*post-compromise security* para grupos).

**Multi-device:** O sistema assume uma sessão por utilizador. Suportar múltiplos dispositivos exigiria sincronização de estado de ratchet ou o mecanismo *Sender Keys* do protocolo Signal para grupos.

**Federação:** O sistema é centralizado num único servidor. Uma arquitetura federada, onde múltiplos servidores interoperam, aumentaria a resiliência e descentralização.

**Interface gráfica:** A interface atual é exclusivamente textual (CLI). Uma GUI melhoraria a usabilidade para utilizadores não técnicos.
