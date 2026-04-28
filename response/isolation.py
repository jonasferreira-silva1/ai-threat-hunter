"""
IsolationManager — AI-Powered Threat Hunter
============================================
Responsabilidade:
    Isolar hosts comprometidos da rede via iptables, preservando acesso de
    management na porta 22 e permitindo reversão completa do isolamento.

    Operações suportadas:
    - isolar_host()         — Adiciona regras DROP para todo tráfego do host,
                              exceto conexões de management na porta 22
    - desfazer_isolamento() — Remove as regras adicionadas e restaura o estado
                              de rede anterior do host

    Em qualquer falha (permissão negada, iptables não encontrado, etc.),
    retorna ResponseAction(status="failed") sem lançar exceção.

Requisitos: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone

from response import ResponseAction

logger = logging.getLogger("threat-hunter.response.isolation")


def _timestamp_utc_agora() -> str:
    """Retorna o timestamp atual em formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


class IsolationManager:
    """
    Gerencia o isolamento de hosts comprometidos via iptables.

    Todas as operações são resilientes a falhas: nenhum método lança exceção —
    em caso de erro, retorna ResponseAction com status="failed".

    O estado de rede anterior de cada host é salvo em ``_hosts_isolados`` para
    permitir reversão completa via ``desfazer_isolamento()``.

    Uso:
        iso = IsolationManager()
        acao = iso.isolar_host("192.168.1.50")
        # → ResponseAction(tipo="host_isolation", status="success", ...)

        acao = iso.desfazer_isolamento("192.168.1.50")
        # → ResponseAction(tipo="host_isolation_undo", status="success", ...)
    """

    def __init__(self) -> None:
        # Rastreia hosts isolados e seu estado de rede anterior.
        # Chave: hostname/IP; Valor: dict com metadados do estado anterior.
        self._hosts_isolados: dict[str, dict] = {}

    # ----------------------------------------------------------
    # API pública
    # ----------------------------------------------------------

    def isolar_host(self, hostname: str) -> ResponseAction:
        """
        Isola o host da rede, bloqueando todo tráfego exceto management (porta 22).

        Salva o estado de rede atual do host em ``_hosts_isolados`` para
        permitir reversão posterior via ``desfazer_isolamento()``.

        Regras iptables adicionadas (nesta ordem):
        1. ACCEPT INPUT de {hostname} na porta 22 (management)
        2. DROP INPUT de {hostname} (bloqueia todo o resto)
        3. DROP OUTPUT para {hostname} (bloqueia saída)

        Args:
            hostname: Endereço IP ou hostname do host a isolar.

        Returns:
            ResponseAction com status="success" ou status="failed".
        """
        timestamp = _timestamp_utc_agora()

        # Salva estado anterior antes de aplicar regras
        estado_anterior: dict = {
            "hostname": hostname,
            "timestamp_isolamento": timestamp,
            "regras_adicionadas": [],
        }

        comandos = [
            ["iptables", "-I", "INPUT", "-s", hostname, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            ["iptables", "-I", "INPUT", "-s", hostname, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-d", hostname, "-j", "DROP"],
        ]

        try:
            for cmd in comandos:
                resultado = subprocess.run(cmd, capture_output=True, text=True)
                if resultado.returncode != 0:
                    erro = resultado.stderr.strip() or f"returncode={resultado.returncode}"
                    logger.error("Falha ao isolar host '%s' (cmd=%s): %s", hostname, cmd, erro)
                    return ResponseAction(
                        tipo="host_isolation",
                        alvo=hostname,
                        status="failed",
                        timestamp=timestamp,
                        erro=erro,
                    )
                estado_anterior["regras_adicionadas"].append(cmd)

        except FileNotFoundError as exc:
            logger.error("iptables não encontrado ao isolar '%s': %s", hostname, exc)
            return ResponseAction(
                tipo="host_isolation",
                alvo=hostname,
                status="failed",
                timestamp=timestamp,
                erro=f"iptables não encontrado: {exc}",
            )
        except Exception as exc:
            logger.error("Erro inesperado ao isolar '%s': %s", hostname, exc)
            return ResponseAction(
                tipo="host_isolation",
                alvo=hostname,
                status="failed",
                timestamp=timestamp,
                erro=str(exc),
            )

        # Persiste estado anterior para reversão
        self._hosts_isolados[hostname] = estado_anterior

        logger.info("Host '%s' isolado com sucesso.", hostname)
        return ResponseAction(
            tipo="host_isolation",
            alvo=hostname,
            status="success",
            timestamp=timestamp,
            detalhes={"hostname": hostname, "regras_adicionadas": len(comandos)},
        )

    def desfazer_isolamento(self, hostname: str) -> ResponseAction:
        """
        Remove o isolamento do host, restaurando a conectividade de rede anterior.

        Remove as regras iptables adicionadas por ``isolar_host()`` e exclui
        o host do dict ``_hosts_isolados``.

        Args:
            hostname: Endereço IP ou hostname do host a desisolar.

        Returns:
            ResponseAction com status="success" ou status="failed".
        """
        timestamp = _timestamp_utc_agora()

        # Determina as regras a remover (inversão das regras de isolamento)
        comandos_remocao = [
            ["iptables", "-D", "INPUT", "-s", hostname, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            ["iptables", "-D", "INPUT", "-s", hostname, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", hostname, "-j", "DROP"],
        ]

        try:
            for cmd in comandos_remocao:
                resultado = subprocess.run(cmd, capture_output=True, text=True)
                if resultado.returncode != 0:
                    erro = resultado.stderr.strip() or f"returncode={resultado.returncode}"
                    logger.error(
                        "Falha ao desfazer isolamento de '%s' (cmd=%s): %s", hostname, cmd, erro
                    )
                    return ResponseAction(
                        tipo="host_isolation_undo",
                        alvo=hostname,
                        status="failed",
                        timestamp=timestamp,
                        erro=erro,
                    )

        except FileNotFoundError as exc:
            logger.error("iptables não encontrado ao desisolar '%s': %s", hostname, exc)
            return ResponseAction(
                tipo="host_isolation_undo",
                alvo=hostname,
                status="failed",
                timestamp=timestamp,
                erro=f"iptables não encontrado: {exc}",
            )
        except Exception as exc:
            logger.error("Erro inesperado ao desisolar '%s': %s", hostname, exc)
            return ResponseAction(
                tipo="host_isolation_undo",
                alvo=hostname,
                status="failed",
                timestamp=timestamp,
                erro=str(exc),
            )

        # Remove host do estado interno
        self._hosts_isolados.pop(hostname, None)

        logger.info("Isolamento de '%s' desfeito com sucesso.", hostname)
        return ResponseAction(
            tipo="host_isolation_undo",
            alvo=hostname,
            status="success",
            timestamp=timestamp,
            detalhes={"hostname": hostname},
        )
