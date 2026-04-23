"""
common/protocol.py
------------------
Constantes partilhadas entre cliente e servidor.
"""

# Limite de mensagens fora de ordem que o ratchet guarda em cache.
MAX_SKIP = 100

# Identificadores HKDF — têm de ser iguais nos dois lados.
HKDF_INFO_ROOT_KEY   = b"double-ratchet-root-v1"
HKDF_INFO_MSG_KEY    = b"double-ratchet-msg-v1"
HKDF_INFO_CHAIN_KEY  = b"double-ratchet-chain-v1"

# URL e certificado TLS (usados pelo cliente; o servidor usa caminhos locais).
SERVER_URL  = "wss://localhost:8765"
TLS_CERT    = "server.crt"
TLS_KEY     = "server.key"

# Ficheiro de base de dados do servidor.
DB_FILE     = "estado_servidor.bin"