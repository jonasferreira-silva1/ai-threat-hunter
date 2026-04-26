"""
FirewallManager — AI-Powered Threat Hunter
==========================================
Responsabilidade:
    Gerenciar regras de bloqueio de IP via iptables, com persistência em
    arquivo para sobreviver a reboots.

    Operações suportadas:
    - bloquear_ip()     — Adiciona regra DROP para o IP (idempotente)
    - desbloquear_ip()  — Remove regra DROP e entrada no arquivo de persistência
    - listar_bloqueados() — Lê o arquivo de persistência e retorna lista de IPs

    Em qualquer falha (permissão negada, iptables não encontrado, etc.),
    retorna ResponseAction(status="failed") sem lançar exceção.

Requisitos: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
"""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from response import ResponseAction

logger = logging.getLogger("threat-hunter.response.firewall")

# Caminho do arquivo de persistência de IPs bloqueados
_ARQUIVO_BLOQUEADOS = Path("/etc/threat-hunter/blocked_ips.conf")


def _timestamp_utc_agora() -> str:
    """Retorna o timestamp atual em formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


class FirewallManager:
    """
    Gerencia regras de bloqueio de IP via iptables.

    Todas as operações são idempotentes e resilientes a falhas: nenhum método
    lança exceção — em caso de erro, retorna ResponseAction com status="failed".

    Uso:
        fw = FirewallManager()
        acao = fw.bloquear_ip("203.0.113.5")
        # → ResponseAction(tipo="firewall_block", status="success", ...)
    """

    # ----------------------------------------------------------
    # API pública
    # ----------------------------------------------------------

    def bloquear_ip(self, ip: str, duracao_segundos: int = 3600) -> ResponseAction:
        """
        Adiciona uma regra DROP para o IP via iptables e persiste no arquivo.

        Verifica primeiro se o IP já está bloqueado (idempotência): se estiver,
        retorna status="success" sem criar regra duplicada.

        Args:
            ip:                Endereço IPv4 a bloquear.
            duracao_segundos:  TTL da regra em segundos (padrão: 3600).
                               Registrado nos detalhes da ação; a remoção
                               automática por TTL não é implementada via iptables
                               nativo (requer at/cron externo).

        Returns:
            ResponseAction com status="success" ou status="failed".
        """
        timestamp = _timestamp_utc_agora()

        # Verifica idempotência: IP já bloqueado?
        if self._ip_ja_bloqueado(ip):
            logger.debug("IP '%s' já está bloqueado — retornando success sem duplicar regra.", ip)
            return ResponseAction(
                tipo="firewall_block",
                alvo=ip,
                status="success",
                timestamp=timestamp,
                detalhes={"ip": ip, "duracao_segundos": duracao_segundos, "idempotente": True},
            )

        # Adiciona regra DROP via iptables
        try:
            resultado = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            logger.error("iptables não encontrado ao bloquear '%s': %s", ip, exc)
            return ResponseAction(
                tipo="firewall_block",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=f"iptables não encontrado: {exc}",
            )
        except Exception as exc:
            logger.error("Erro inesperado ao bloquear '%s': %s", ip, exc)
            return ResponseAction(
                tipo="firewall_block",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=str(exc),
            )

        if resultado.returncode != 0:
            erro = resultado.stderr.strip() or f"returncode={resultado.returncode}"
            logger.error("Falha ao bloquear IP '%s': %s", ip, erro)
            return ResponseAction(
                tipo="firewall_block",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=erro,
            )

        # Persiste no arquivo
        self._persistir_ip(ip)

        logger.info("IP '%s' bloqueado com sucesso.", ip)
        return ResponseAction(
            tipo="firewall_block",
            alvo=ip,
            status="success",
            timestamp=timestamp,
            detalhes={"ip": ip, "duracao_segundos": duracao_segundos, "idempotente": False},
        )

    def desbloquear_ip(self, ip: str) -> ResponseAction:
        """
        Remove a regra DROP para o IP via iptables e do arquivo de persistência.

        Args:
            ip: Endereço IPv4 a desbloquear.

        Returns:
            ResponseAction com status="success" ou status="failed".
        """
        timestamp = _timestamp_utc_agora()

        try:
            resultado = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            logger.error("iptables não encontrado ao desbloquear '%s': %s", ip, exc)
            return ResponseAction(
                tipo="firewall_unblock",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=f"iptables não encontrado: {exc}",
            )
        except Exception as exc:
            logger.error("Erro inesperado ao desbloquear '%s': %s", ip, exc)
            return ResponseAction(
                tipo="firewall_unblock",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=str(exc),
            )

        if resultado.returncode != 0:
            erro = resultado.stderr.strip() or f"returncode={resultado.returncode}"
            logger.error("Falha ao desbloquear IP '%s': %s", ip, erro)
            return ResponseAction(
                tipo="firewall_unblock",
                alvo=ip,
                status="failed",
                timestamp=timestamp,
                erro=erro,
            )

        # Remove do arquivo de persistência
        self._remover_ip(ip)

        logger.info("IP '%s' desbloqueado com sucesso.", ip)
        return ResponseAction(
            tipo="firewall_unblock",
            alvo=ip,
            status="success",
            timestamp=timestamp,
            detalhes={"ip": ip},
        )

    def listar_bloqueados(self) -> list[str]:
        """
        Retorna a lista de IPs atualmente bloqueados, lida do arquivo de persistência.

        Returns:
            Lista de strings com endereços IPv4 bloqueados.
            Retorna lista vazia se o arquivo não existir ou em caso de erro.
        """
        if not _ARQUIVO_BLOQUEADOS.exists():
            return []

        try:
            linhas = _ARQUIVO_BLOQUEADOS.read_text(encoding="utf-8").splitlines()
            return [linha.strip() for linha in linhas if linha.strip()]
        except Exception as exc:
            logger.error("Erro ao ler arquivo de IPs bloqueados: %s", exc)
            return []

    # ----------------------------------------------------------
    # Métodos internos
    # ----------------------------------------------------------

    def _ip_ja_bloqueado(self, ip: str) -> bool:
        """
        Verifica se o IP já possui regra DROP no iptables.

        Usa ``iptables -C INPUT -s {ip} -j DROP``:
        - returncode 0  → regra existe
        - returncode != 0 → regra não existe

        Args:
            ip: Endereço IPv4 a verificar.

        Returns:
            True se a regra já existe, False caso contrário ou em caso de erro.
        """
        try:
            resultado = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
            )
            return resultado.returncode == 0
        except Exception:
            return False

    def _persistir_ip(self, ip: str) -> None:
        """
        Adiciona o IP ao arquivo de persistência, criando o diretório se necessário.

        Args:
            ip: Endereço IPv4 a persistir.
        """
        try:
            _ARQUIVO_BLOQUEADOS.parent.mkdir(parents=True, exist_ok=True)
            ips_atuais = self.listar_bloqueados()
            if ip not in ips_atuais:
                with _ARQUIVO_BLOQUEADOS.open("a", encoding="utf-8") as f:
                    f.write(f"{ip}\n")
        except Exception as exc:
            logger.error("Erro ao persistir IP '%s' no arquivo: %s", ip, exc)

    def _remover_ip(self, ip: str) -> None:
        """
        Remove o IP do arquivo de persistência.

        Args:
            ip: Endereço IPv4 a remover.
        """
        if not _ARQUIVO_BLOQUEADOS.exists():
            return

        try:
            ips_atuais = self.listar_bloqueados()
            ips_filtrados = [i for i in ips_atuais if i != ip]
            _ARQUIVO_BLOQUEADOS.write_text("\n".join(ips_filtrados) + ("\n" if ips_filtrados else ""), encoding="utf-8")
        except Exception as exc:
            logger.error("Erro ao remover IP '%s' do arquivo: %s", ip, exc)
