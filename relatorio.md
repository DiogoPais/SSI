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
| `common/` | `crypto.py`, `pki.py`, `protocol.py`, `ratchet.py` | Primitivas partilhadas entre cliente e servidor |
| `server/` | `servidor.py`, `auth.py`, `handlers.py`, `persistence.py` | Lógica do servidor |
| `client/` | `ws_client.py`, `crypto.py`, `Cliente.py` | Lógica e interface do cliente |

### 1.3 Servidor

O servidor (`servidor.py`) é responsável por:

- Gerir o registo e autenticação de utilizadores.
- Atuar como **Autoridade de Certificação (CA)**, emitindo certificados Ed25519 a cada utilizador no momento do registo.
- Encaminhar mensagens cifradas entre clientes (online ou offline).
- Gerir grupos e distribuir as respetivas key shares.
- Servir de canal de sinalização para ligações P2P diretas.
- Persistir o estado de forma cifrada em disco (`estado_servidor.bin`).

O servidor escuta ligações WebSocket sobre TLS na porta `8765` (`wss://localhost:8765`).

### 1.4 Cliente

O cliente está dividido em duas camadas:

- **`ws_client.py` (ClienteWS):** toda a lógica de rede, criptografia e gestão de sessões ratchet. Gere o estado local de cada sessão E2EE e comunica com o servidor através de WebSocket sobre TLS.
- **`Cliente.py` (CLI):** interface de linha de comandos. Faz parsing dos comandos do utilizador e delega para a `ClienteWS`.

O estado do cliente (chaves privadas, sessões ratchet, grupos) é persistido localmente em `estado_<username>.bin`, cifrado com AES-GCM derivado da password do utilizador via PBKDF2.

### 1.5 Gestão de Chaves

Cada utilizador possui:

- **Chave de identidade X25519** (`identity_priv`): chave estática de longa duração usada para o handshake inicial das sessões Double Ratchet e para derivar chaves de grupo.
- **Certificado Ed25519** emitido pela CA do servidor no momento do registo, que associa o `username` à chave pública de identidade.

O servidor mantém:

- **Chave X25519** de transporte: usada para cifrar os payloads de registo/login enviados pelo cliente ao servidor (ECDH efémero + AES-GCM).
- **Chave privada Ed25519 da CA**: usada para assinar certificados de utilizadores.
- **Segredo JWT**: usado para emitir e verificar tokens de sessão.

---

## 2. Fluxos de Comunicação

### 2.1 Handshake TLS e Verificação da CA

Ao ligar-se, o cliente:

1. Estabelece uma ligação WebSocket com TLS, verificando o certificado TLS do servidor.
2. Recebe um `server_hello` com a chave pública X25519 do servidor, a chave pública da CA e uma assinatura Ed25519 da chave do servidor, feita pela CA.
3. Compara a CA recebida com a CA previamente guardada em `ca_pinned.pub` (CA pinning). Se não coincidir, rejeita a ligação como possível ataque MITM.
4. Verifica a assinatura Ed25519, confirmando que a chave de transporte do servidor é autêntica.

### 2.2 Registo

1. O cliente gera a sua chave de identidade X25519 localmente.
2. Deriva um `salt` aleatório e um `hash` PBKDF2 da password.
3. Cifra o payload `{salt, hash, chat_pub_key}` com ECDH efémero + AES-GCM, usando a chave pública X25519 do servidor.
4. Envia o payload cifrado. O servidor decifra, regista o utilizador e emite um certificado Ed25519 associando o `username` à `chat_pub_key`.
5. O certificado é devolvido ao cliente e guardado no estado local cifrado.

### 2.3 Login (Challenge-Response)

O login segue um protocolo de challenge-response em dois passos:

1. **`get_challenge`:** o cliente pede um desafio. O servidor gera 32 bytes aleatórios e devolve-os juntamente com o `salt` do utilizador.
2. **`login`:** o cliente deriva o hash da password com PBKDF2 e calcula `HMAC-SHA256(hash_password, challenge)`. Este valor é cifrado com ECDH efémero e enviado ao servidor. O servidor verifica o HMAC e, se correto, emite um JWT com validade de 2 horas.

A password nunca viaja em claro, nem o hash diretamente — apenas a resposta HMAC ao desafio, dentro de uma camada de cifragem ECDH.

### 2.4 Envio de Mensagem Direta

1. O remetente obtém a chave pública e o certificado Ed25519 do destinatário junto do servidor (`get_key`).
2. Verifica o certificado com a CA local.
3. Se for a primeira mensagem entre os dois peers, inicia uma sessão Double Ratchet com base num shared secret ECDH entre as suas chaves de identidade estáticas.
4. Cifra o texto com o Double Ratchet (que usa AES-GCM internamente).
5. Envia o payload cifrado ao servidor, que o encaminha para o destinatário (online) ou guarda na fila offline.

### 2.5 Receção de Mensagem

O cliente corre um loop de escuta contínuo (`_escutar`) que processa mensagens push do servidor. Ao receber uma mensagem:

1. Verifica o certificado Ed25519 do remetente.
2. Se não houver sessão com este peer, inicializa-a como recetor (`is_initiator=False`).
3. Decifra com o Double Ratchet, avançando o ratchet simétrico.

### 2.6 Mensagens de Grupo

**Criação:**
1. O criador gera uma `group_key` aleatória de 32 bytes.
2. Para cada membro, cifra a `group_key` com ECDH efémero + AES-GCM, usando a chave pública de identidade do membro (`cifrar_chave_grupo`).
3. Envia ao servidor o grupo com todas as key shares cifradas.
4. O servidor notifica cada membro (online ou offline via fila).

**Envio de mensagem de grupo:**
1. O remetente avança o seu ratchet simétrico pessoal dentro do grupo (derivado com HKDF da `group_key` e do seu `username`).
2. Cifra o texto com AES-GCM, usando o número de sequência e o `username` como AAD para autenticidade.
3. O servidor distribui o payload cifrado a todos os membros.

**Receção de mensagem de grupo:**
1. O recetor decifra a sua key share recebida no convite.
2. Deriva a chain do remetente com HKDF a partir da `group_key`.
3. Avança o ratchet simétrico do remetente até ao número de sequência correto e decifra.

### 2.7 Modo P2P Direto

1. O cliente que inicia (`p2p start`) arranca um servidor WebSocket local com TLS na porta indicada.
2. Envia ao peer um convite via servidor (`p2p invite`), com o endereço e um token de autenticação único.
3. O peer recebe o sinal, liga-se diretamente ao servidor P2P e autentica-se com o token.
4. As mensagens seguintes entre os dois peers passam diretamente, sem passar pelo servidor central, usando o Double Ratchet já existente entre eles.

---

## 3. Funcionalidades Implementadas

### 3.1 Funcionalidades Base

- **Registo de utilizadores** com hash de password (PBKDF2) e cifragem do payload de registo.
- **Login challenge-response** com HMAC-SHA256 e emissão de JWT.
- **Mensagens diretas E2EE** com Double Ratchet.
- **Interface de linha de comandos (CLI)** com comandos textuais.
- **Logout** com limpeza completa do estado sensível em memória.

### 3.2 Valorizações Implementadas

#### Mensagens Offline
O servidor guarda as mensagens (já cifradas) na `offline_queue` quando o destinatário não está ligado. Quando o utilizador faz login, todas as mensagens pendentes são entregues imediatamente. O mesmo mecanismo aplica-se a convites de grupo.

#### Entidade de Certificação (PKI)
O servidor atua como CA self-signed com uma chave Ed25519 própria. No momento do registo, emite um certificado no formato:
```
payload = "username|chat_pub_hex|timestamp"
certificado = payload_hex + "." + assinatura_Ed25519_hex
```
O cliente verifica este certificado antes de iniciar qualquer sessão, garantindo autenticidade da chave pública do peer. O cliente usa CA pinning: compara a CA recebida do servidor com a gravada localmente em `ca_pinned.pub`, detetando qualquer tentativa de substituição.

Como fallback para peers sem certificado válido, o sistema usa **Trust On First Use (TOFU)**: a primeira chave pública associada a um `username` é guardada como confiável, e qualquer alteração subsequente é sinalizada como possível ataque.

#### Modo Descentralizado P2P
Os clientes podem estabelecer ligações WebSocket diretas entre si, dispensando o servidor como relay para as mensagens. O servidor funciona apenas como canal de sinalização para a troca inicial de endereços. As mensagens P2P continuam a usar o Double Ratchet da sessão existente.

#### Mensagens de Grupo
Grupos com múltiplos membros, com distribuição segura de chave de grupo via ECDH efémero por membro. Cada membro tem o seu próprio ratchet simétrico dentro do grupo, com números de sequência e proteção contra replay.

#### Forward Secrecy (Double Ratchet)
O protocolo Double Ratchet garante forward secrecy a dois níveis:
- **Ratchet simétrico:** cada mensagem usa uma message key diferente, descartada após uso.
- **Ratchet DH:** a cada nova ronda de envio, gera-se um novo par X25519 efémero, descartando o par anterior. Mesmo que um atacante obtenha a chain key atual, não consegue derivar chaves de mensagens anteriores.

---

## 4. Modelo de Segurança

### 4.1 Primitivas Criptográficas

| Primitiva | Algoritmo | Utilização |
|---|---|---|
| Troca de chaves | X25519 (ECDH) | Handshake Double Ratchet; cifragem de payloads de autenticação; key shares de grupo |
| Cifragem simétrica | AES-256-GCM | Cifragem de mensagens, payloads de autenticação e estado local |
| Derivação de chave | HKDF-SHA256 | Derivação de root key, chain key, message key e chave de transporte |
| Hash de password | PBKDF2-SHA256 (600 000 iterações) | Derivação de hash de password para autenticação e cifragem do estado local |
| Assinatura digital | Ed25519 | Certificados de utilizador emitidos pela CA; assinatura da chave do servidor |
| Autenticação de sessão | JWT (HS256) | Tokens de sessão para operações autenticadas |
| Autenticação de mensagem | AES-GCM (AAD) | Header do ratchet e identidade do remetente em grupos autenticados pelo MAC |
| HMAC | HMAC-SHA256 | Resposta ao desafio de login |

### 4.2 Justificação e Comparação das Primitivas Escolhidas

#### X25519 vs. alternativas de troca de chaves (RSA, P-256, DH clássico)

Para a troca de chaves foi escolhido **X25519 (ECDH sobre Curve25519)**. As alternativas mais comuns seriam RSA (com cifra assimétrica direta), ECDH sobre curvas NIST como P-256, ou Diffie-Hellman clássico sobre grupos multiplicativos (FFDH).

O RSA foi descartado desde o início porque não oferece forward secrecy de forma nativa — se a chave privada for comprometida, todo o histórico de comunicações pode ser decifrado retroativamente. Além disso, para níveis de segurança equivalentes, as chaves RSA são ordens de magnitude maiores (2048–4096 bits vs. 32 bytes do X25519), tornando-o menos eficiente.

O FFDH clássico tem os mesmos problemas de dimensão de chave e é vulnerável a ataques de Logjam quando grupos estandardizados são reutilizados entre implementações.

O P-256 (secp256r1) seria uma alternativa razoável em termos de segurança, mas a Curve25519 apresenta vantagens importantes: a sua implementação é resistente a ataques de timing por design (sem necessidade de operações condicionais secretas), os parâmetros da curva foram gerados de forma transparente e verificável (ao contrário do P-256, cujos parâmetros NIST levantam dúvidas históricas sobre possível backdoor), e a performance é superior. Por estas razões, o X25519 é hoje a escolha preferida em protocolos modernos como TLS 1.3, Signal e WireGuard.

#### AES-256-GCM vs. alternativas de cifragem simétrica (AES-CBC, ChaCha20-Poly1305, AES-CTR)

Para cifragem simétrica foi escolhido **AES-256-GCM**. As alternativas principais seriam AES-CBC (com HMAC separado), AES-CTR (sem autenticação), ou ChaCha20-Poly1305.

O AES-CBC com HMAC separado é um padrão antigo que exige implementar corretamente o esquema MAC-then-Encrypt vs. Encrypt-then-MAC — uma fonte histórica de vulnerabilidades graves como o ataque BEAST e ataques de padding oracle. O AES-GCM integra autenticação e cifragem numa só operação (AEAD), eliminando esta classe de erros.

O AES-CTR sem autenticação foi excluído por razões óbvias: não oferece integridade nem autenticidade, permitindo a um atacante alterar bits do ciphertext de forma controlada.

O ChaCha20-Poly1305 seria uma alternativa moderna igualmente válida em termos de segurança, com a vantagem de ser mais eficiente em hardware sem instruções AES-NI. No entanto, o AES-256-GCM beneficia de aceleração por hardware em praticamente todos os processadores modernos (via AES-NI), o que o torna igualmente rápido na prática, e a sua suporte na biblioteca `cryptography` do Python é igualmente maduro e auditado.

A variante AES-**256** (vs. AES-128) foi escolhida para oferecer margem de segurança adicional, especialmente relevante no contexto de chaves derivadas de passwords ou shared secrets.

#### HKDF-SHA256 vs. alternativas de derivação de chave (KDF direta, concatenação simples, PBKDF2 para chaves efémeras)

O **HKDF (HMAC-based Key Derivation Function)** com SHA-256 é o padrão recomendado pelo NIST (RFC 5869) para derivação de chaves a partir de material de alta entropia como shared secrets ECDH.

A alternativa de usar o output ECDH diretamente como chave AES seria incorreta: o output de X25519 não está uniformemente distribuído no espaço de chaves AES e pode ter estrutura que um adversário poderia explorar. O HKDF aplica um passo de extração (HMAC-SHA256 com salt) seguido de expansão, produzindo bytes pseudoaleatórios de alta qualidade.

O uso de SHA-256 (em vez de SHA-512 ou SHA-3) é suficiente para os 256 bits de segurança pretendidos, e a sua implementação é amplamente auditada e eficiente.

O PBKDF2 é reservado exclusivamente para situações onde o material de entrada tem baixa entropia (passwords humanas), onde o seu custo computacional elevado é uma vantagem que torna ataques de força bruta economicamente proibitivos. Usar PBKDF2 para chaves efémeras seria desnecessariamente lento sem qualquer benefício.

#### PBKDF2-SHA256 (600 000 iterações) vs. alternativas de hash de password (bcrypt, scrypt, Argon2, SHA-256 simples)

Para proteção de passwords foi escolhido **PBKDF2-SHA256 com 600 000 iterações**. As alternativas modernas incluem bcrypt, scrypt e Argon2id.

Um hash simples como SHA-256 foi excluído imediatamente: sem custo computacional deliberado, um atacante com GPU pode testar biliões de passwords por segundo.

O bcrypt é um algoritmo maduro e bem estudado, mas tem um limite de 72 caracteres de password e não permite configurar o uso de memória (tornando-o mais vulnerável a ataques com hardware paralelo como FPGAs e ASICs).

O scrypt e o Argon2id são superiores ao PBKDF2 em resistência a hardware especializado, pois incorporam também um parâmetro de custo de memória que dificulta a paralelização. Seriam escolhas ideais num sistema de produção.

A razão pela qual o PBKDF2 foi mantido é que é o algoritmo disponível nativamente na biblioteca `cryptography` do Python sem dependências adicionais, e com 600 000 iterações (o valor recomendado pelo OWASP em 2023 para PBKDF2-SHA256) oferece proteção adequada no contexto deste projeto. O salt aleatório de 16 bytes por utilizador garante que dois utilizadores com a mesma password produzem hashes diferentes, eliminando ataques de rainbow table.

#### Ed25519 vs. alternativas de assinatura digital (RSA-PSS, ECDSA P-256, RSA-PKCS1)

Para assinaturas digitais (certificados CA e autenticação do servidor) foi escolhido **Ed25519**.

O RSA-PKCS1 é considerado legado — é vulnerável a ataques de bleichenbacher e não oferece forward secrecy. O RSA-PSS é mais seguro mas ainda sofre dos problemas de dimensão de chave e performance.

O ECDSA sobre P-256 tem um problema crítico: a sua segurança depende da qualidade do gerador de números aleatórios no momento da assinatura. Se o nonce usado na assinatura for previsível ou reutilizado, a chave privada pode ser recuperada — esta vulnerabilidade foi explorada em vários ataques reais, incluindo na Sony PlayStation 3. O Ed25519, por ser um esquema determinístico (EdDSA), elimina completamente este risco: o nonce é derivado deterministicamente da chave privada e da mensagem, sem necessidade de aleatoriedade no ato de assinar.

Ed25519 oferece ainda chaves de apenas 32 bytes, assinaturas de 64 bytes, verificação extremamente rápida, e resistência a ataques de timing por design. É hoje o esquema de assinatura preferido em protocolos modernos.

#### Double Ratchet vs. alternativas de protocolo de mensagens (TLS puro, PGP, SRP, cifra estática de sessão)

O **Double Ratchet** é a escolha nuclear deste sistema, e é o que o distingue de implementações mais simples.

Uma abordagem ingénua seria cifrar todas as mensagens com uma chave de sessão estática derivada no início da conversa. Esta abordagem é simples mas catastrófica do ponto de vista de segurança: se a chave de sessão for descoberta, todas as mensagens passadas e futuras ficam expostas.

O PGP (usado para email cifrado) usa cifra de mensagem com a chave pública do destinatário diretamente, sem forward secrecy e sem proteção contra replay. O histórico de comunicações fica exposto se a chave privada for comprometida.

O TLS oferece forward secrecy ao nível da sessão de transporte, mas não ao nível das mensagens individuais dentro de uma sessão: se o canal TLS for decifrado, todas as mensagens da sessão ficam expostas.

O Double Ratchet combina um **ratchet DH** (que rota as chaves de sessão a cada nova ronda, garantindo *break-in recovery*) com um **ratchet simétrico** (que gera uma chave única por mensagem, garantindo que comprometer uma mensagem não compromete as anteriores ou as seguintes). Esta combinação fornece simultaneamente **forward secrecy** e **break-in recovery**, propriedades que nenhuma das alternativas acima oferece de forma completa. É exatamente o protocolo usado pelo Signal, WhatsApp e outros sistemas de mensagens seguros de referência.

### 4.3 Garantias de Segurança

**Confidencialidade:** As mensagens são cifradas ponta-a-ponta com AES-256-GCM. O servidor recebe apenas texto cifrado e nunca tem acesso às chaves de sessão, que são derivadas localmente nos clientes via ECDH.

**Integridade:** O AES-GCM inclui um MAC de 128 bits que autentica simultaneamente o ciphertext e o header (nonce + chave pública DH + número de sequência). Qualquer adulteração invalida o MAC.

**Autenticidade de utilizadores:** Os certificados Ed25519 emitidos pela CA garantem a ligação entre um `username` e a respetiva chave pública. O cliente verifica sempre o certificado antes de iniciar uma sessão ou aceitar uma mensagem.

**Proteção contra MITM:** O CA pinning impede que um atacante no canal substitua a CA por uma sua. A assinatura Ed25519 da chave de transporte do servidor, feita pela CA, garante que o cliente está a falar com o servidor legítimo e não com um intermediário.

**Forward Secrecy:** O Double Ratchet garante que a comprometimento de uma chave de sessão não compromete mensagens passadas. As message keys são descartadas após uso e os pares DH efémeros são descartados após cada ronda de ratchet.

**Break-in Recovery:** O DH ratchet recupera da comprometimento das chain keys: assim que o ratchet DH roda (nova chave efémera), um atacante que tenha obtido a chain key anterior perde acesso às mensagens seguintes.

**Proteção contra Replay:** O número de sequência é verificado em cada mensagem. Mensagens com sequência menor ou igual à última recebida são rejeitadas. Mensagens fora de ordem são tratadas com uma cache de chaves limitada a `MAX_SKIP=100` entradas.

**Proteção da password:** A password nunca é transmitida. O registo envia apenas o hash PBKDF2. O login usa challenge-response HMAC, de forma que mesmo que o canal de transporte seja comprometido, a password não é revelada.

**Confidencialidade do estado local:** O estado de cada cliente (chaves privadas, sessões, grupos) é cifrado em disco com AES-256-GCM, com chave derivada da password via PBKDF2 com salt aleatório e 600 000 iterações.

**Cifragem do estado do servidor:** O servidor cifra a sua base de dados completa com AES-256-GCM e PBKDF2, protegendo os dados mesmo em caso de acesso físico ao disco.

**Autenticidade nas mensagens de grupo:** O `username` do remetente e o número de sequência são usados como AAD no AES-GCM, impedindo que um membro se faça passar por outro ou reutilize mensagens antigas.

### 4.4 Modelo de Ameaça

O sistema foi desenhado para resistir a:

- **Servidor curioso:** não tem acesso ao conteúdo das mensagens, às chaves privadas dos clientes, nem às chaves de grupo.
- **Atacante na rede (MITM passivo):** toda a comunicação é cifrada com TLS e com E2EE.
- **Atacante na rede (MITM ativo):** o CA pinning e a verificação de certificados Ed25519 impedem a substituição de chaves.
- **Comprometimento de chave de sessão:** o Double Ratchet limita o impacto a um número limitado de mensagens.
- **Replay attacks:** números de sequência e descarte de message keys após uso.

---

## 5. Limitações Conhecidas

**Sem renovação de chaves de longa duração:** A chave de identidade X25519 de cada utilizador é gerada no registo e mantida indefinidamente. Não existe mecanismo de rotação ou revogação de chaves comprometidas.

**CA única centralizada:** O servidor é simultaneamente relay e CA. Um servidor comprometido poderia emitir certificados falsos. Num sistema de produção seria desejável uma CA separada ou um modelo de confiança distribuído (web-of-trust).

**Sem Perfect Forward Secrecy no handshake inicial:** O handshake do Double Ratchet usa as chaves estáticas de identidade para o primeiro passo DH. Se a chave estática de um utilizador for comprometida, o primeiro shared secret pode ser derivado retroativamente por um atacante que tenha gravado o tráfego.

**JWT sem revogação:** Os tokens JWT têm validade de 2 horas e não existem listas de revogação. Um token válido furtado mantém acesso até expirar.

**Sem anonimato de metadados:** O servidor conhece os padrões de comunicação: quem envia mensagens a quem, quando e com que frequência (mesmo sem ver o conteúdo).

**Chave de grupo estática:** A `group_key` de cada grupo não é renovada quando membros saem. Não existe mecanismo de exclusão de membros com rotação de chave.

**Sem proteção contra Denial of Service:** Não há rate limiting ou mecanismos de proteção contra abuso do servidor.

**Sem verificação cruzada de certificados entre clientes:** Os clientes confiam nos certificados emitidos pela CA do servidor, mas não existe mecanismo para os utilizadores verificarem mutuamente as suas identidades fora de banda (ex: comparação de fingerprints).

---

## 6. Melhorias Não Implementadas

**Extended Triple Diffie-Hellman (X3DH):** O protocolo Signal usa X3DH para o handshake inicial, que inclui chaves efémeras pré-publicadas (*prekeys*) para garantir forward secrecy mesmo antes da primeira mensagem. A implementação atual usa apenas as chaves estáticas para o shared secret inicial, o que não oferece essa proteção.

**Multi-device:** O sistema assume uma sessão por utilizador. Suportar múltiplos dispositivos do mesmo utilizador exigiria sincronização de estado de ratchet ou a utilização de um mecanismo como o *Sender Keys* do protocolo Signal para grupos.

**Rotação e revogação de certificados:** Implementar um mecanismo de revogação de certificados e de renovação de chave de identidade aumentaria a resiliência a comprometimento de chave a longo prazo.

**Exclusão dinâmica de membros de grupo:** Com rotação de `group_key`, seria possível remover membros de grupos com garantia de que não acedem a mensagens futuras (*post-compromise security* para grupos).

**Interface gráfica:** A interface atual é exclusivamente textual (CLI). Uma GUI melhoraria a usabilidade para utilizadores não técnicos.

**Federação:** O sistema é centralizado num único servidor. Uma arquitetura federada, onde múltiplos servidores interoperam, aumentaria a resiliência e descentralização.
