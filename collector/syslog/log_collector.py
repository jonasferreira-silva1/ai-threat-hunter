"""
Coletor de Logs do Sistema — AI-Powered Threat Hunter
======================================================
Responsabilidade:
    Lê logs do sistema operacional em tempo real,
    normaliza cada evento no schema padrão do projeto
    e envia para o Logstash via TCP.

Fontes suportadas:
    - /var/log/auth.log  (autenticação SSH, sudo, login)
    - /var/log/syslog    (eventos gerais do sistema)

Uso:
    python log_collector.py

Variáveis de ambiente necessárias (.env):
    COLLECTOR_HOST  — hostname do Logstash (padrão: localhost)
    COLLECTOR_PORT  — porta TCP do Logstash  (padrão: 5044)
    LOG_LEVEL       — nível de log da aplicação (padrão: INFO)
"""

import os
import re
import json
import time
import socket
import logging
from datetime import datetime, timezone
from pathlib import Path

# =============================================================
# Configuração de logging da própria aplicação
# =============================================================
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("threat-hunter.collector")


# =============================================================
# Constantes
# =============================================================

# Arquivos de log monitorados
LOG_FILES = [
    Path("/var/log/auth.log"),
    Path("/var/log/syslog"),
]

# Destino dos eventos normalizados
LOGSTASH_HOST = os.getenv("COLLECTOR_HOST", "localhost")
LOGSTASH_PORT = int(os.getenv("COLLECTOR_PORT", 5044))

# Intervalo de polling quando não há novas linhas (segundos)
POLL_INTERVAL = 1.0


# =============================================================
# Padrões de detecção via expressões regulares
# Cada padrão mapeia para um event_type do schema padrão
# =============================================================
PATTERNS = {
    # Falha de autenticação SSH
    "auth_failure": re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    # Autenticação SSH bem-sucedida
    "auth_success": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
    ),
    # Escalonamento de privilégio via sudo
    "privilege_escalation": re.compile(
        r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    ),
    # Sessão encerrada
    "session_closed": re.compile(
        r"session closed for user (\S+)"
    ),
}


# =============================================================
# Funções de normalização
# =============================================================

def normalizar_evento(linha: str, arquivo: str) -> dict | None:
    """
    Tenta identificar o tipo do evento na linha de log
    e retorna um dicionário no schema padrão do projeto.

    Retorna None se a linha não corresponder a nenhum padrão conhecido.

    Args:
        linha:   Linha bruta do arquivo de log.
        arquivo: Caminho do arquivo de origem (para rastreabilidade).

    Returns:
        Dicionário normalizado ou None.
    """
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(linha)
        if not match:
            continue

        # Base comum a todos os eventos
        evento = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "source":     arquivo,
            "raw_log":    linha.strip(),
            "severity":   None,   # Será preenchido pelo Logstash/ML
            "ml_score":   -1,     # -1 = ainda não processado
        }

        # Enriquecimento específico por tipo de evento
        if event_type in ("auth_failure", "auth_success"):
            evento["username"]  = match.group(1)
            evento["source_ip"] = match.group(2)

        elif event_type == "privilege_escalation":
            evento["username"] = match.group(1)
            evento["command"]  = match.group(2).strip()

        elif event_type == "session_closed":
            evento["username"] = match.group(1)

        return evento

    return None  # Linha não reconhecida — descartada silenciosamente


# =============================================================
# Conexão com o Logstash
# =============================================================

def conectar_logstash() -> socket.socket:
    """
    Cria e retorna uma conexão TCP com o Logstash.
    Tenta reconectar indefinidamente em caso de falha,
    com backoff exponencial até 60 segundos.

    Returns:
        Socket TCP conectado ao Logstash.
    """
    tentativa = 0
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
            logger.info(f"Conectado ao Logstash em {LOGSTASH_HOST}:{LOGSTASH_PORT}")
            return sock
        except ConnectionRefusedError:
            espera = min(2 ** tentativa, 60)
            logger.warning(
                f"Logstash indisponível. Tentativa {tentativa + 1}. "
                f"Aguardando {espera}s..."
            )
            time.sleep(espera)
            tentativa += 1


def enviar_evento(sock: socket.socket, evento: dict) -> None:
    """
    Serializa o evento em JSON e envia via TCP para o Logstash.
    Cada evento é terminado com newline (protocolo json_lines).

    Args:
        sock:   Socket TCP conectado.
        evento: Dicionário do evento normalizado.
    """
    payload = json.dumps(evento) + "\n"
    sock.sendall(payload.encode("utf-8"))
    logger.debug(f"Evento enviado: {evento['event_type']} | {evento.get('source_ip', 'N/A')}")


# =============================================================
# Monitoramento de arquivos (tail -f)
# =============================================================

def monitorar_arquivo(caminho: Path, sock: socket.socket) -> None:
    """
    Monitora um arquivo de log em tempo real (comportamento de tail -f).
    Processa apenas linhas novas adicionadas após o início da execução.

    Args:
        caminho: Caminho do arquivo de log a monitorar.
        sock:    Socket TCP conectado ao Logstash.
    """
    if not caminho.exists():
        logger.warning(f"Arquivo não encontrado, ignorando: {caminho}")
        return

    logger.info(f"Monitorando: {caminho}")

    with open(caminho, "r", encoding="utf-8", errors="replace") as arquivo:
        # Vai para o final do arquivo — ignora histórico, processa apenas novos eventos
        arquivo.seek(0, 2)

        while True:
            linha = arquivo.readline()

            if not linha:
                # Sem novas linhas — aguarda antes de tentar novamente
                time.sleep(POLL_INTERVAL)
                continue

            evento = normalizar_evento(linha, str(caminho))

            if evento:
                try:
                    enviar_evento(sock, evento)
                except (BrokenPipeError, OSError):
                    logger.error("Conexão com Logstash perdida. Reconectando...")
                    sock = conectar_logstash()
                    enviar_evento(sock, evento)


# =============================================================
# Ponto de entrada
# =============================================================

def main() -> None:
    """
    Inicializa o coletor:
    1. Conecta ao Logstash
    2. Inicia monitoramento dos arquivos de log em paralelo
    """
    logger.info("AI-Powered Threat Hunter — Coletor de Logs iniciado")
    logger.info(f"Destino: {LOGSTASH_HOST}:{LOGSTASH_PORT}")

    sock = conectar_logstash()

    # Monitora todos os arquivos configurados
    # Em produção, usar threads ou asyncio para paralelismo real
    for log_file in LOG_FILES:
        monitorar_arquivo(log_file, sock)


if __name__ == "__main__":
    main()
