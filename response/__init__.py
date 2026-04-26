"""
Camada 5 — Resposta Automática — AI-Powered Threat Hunter
=========================================================
Responsabilidade:
    Executar ações defensivas automáticas para incidentes com score >= 80,
    e notificações para incidentes com score >= 60.

Componentes:
    FirewallManager        — Bloqueio de IPs via iptables/nftables.
    IsolationManager       — Isolamento de hosts comprometidos da rede.
    NotificationDispatcher — Envio de notificações via Slack, Telegram e e-mail.
    TicketCreator          — Criação de tickets no sistema de gestão.
    ResponseOrchestrator   — Orquestra todas as ações de resposta.

Classes exportadas:
    ResponseAction         — Representa uma ação de resposta executada (sucesso ou falha).
    FirewallManager
    IsolationManager
    NotificationDispatcher
    TicketCreator
    ResponseOrchestrator
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResponseAction:
    """
    Representa uma ação de resposta automática executada pelo sistema.

    Atributos:
        tipo:       Tipo da ação executada.
                    Valores: firewall_block | host_isolation | notification | ticket
        alvo:       Alvo da ação (IP, hostname, canal de notificação, etc.).
        status:     Estado final da execução.
                    Valores: pending | success | failed
        timestamp:  Momento da execução em formato ISO 8601 UTC.
        detalhes:   Informações adicionais sobre a execução (parâmetros, resultado, etc.).
        erro:       Mensagem de erro descritiva quando status == "failed"; None caso contrário.
    """

    tipo: str
    alvo: str
    status: str
    timestamp: str
    detalhes: dict = field(default_factory=dict)
    erro: str | None = None


# As demais classes serão exportadas aqui à medida que forem implementadas
# nas tasks subsequentes (8, 9, 10 e 11).
