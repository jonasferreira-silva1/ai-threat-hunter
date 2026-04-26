"""
Fixtures compartilhadas para os testes da Camada 5 — Resposta Automática.

Fornece mocks de subprocess (iptables) e de HTTP (httpx) para que os testes
sejam executados sem dependências externas, além de IncidentReports prontos
para uso nos testes de FirewallManager, NotificationDispatcher e Orchestrator.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


# =============================================================
# Fixtures de mock — subprocess (iptables)
# =============================================================

@pytest.fixture
def mock_subprocess_sucesso(monkeypatch):
    """
    Mock de ``subprocess.run`` que simula execução bem-sucedida de iptables.

    Retorna um objeto com ``returncode=0`` e ``stdout``/``stderr`` vazios,
    representando um comando iptables executado sem erros.
    """
    resultado = MagicMock()
    resultado.returncode = 0
    resultado.stdout = ""
    resultado.stderr = ""

    mock = MagicMock(return_value=resultado)
    monkeypatch.setattr("subprocess.run", mock)
    return mock


@pytest.fixture
def mock_subprocess_falha_permissao(monkeypatch):
    """
    Mock de ``subprocess.run`` que simula falha por permissão negada.

    Retorna um objeto com ``returncode=1`` e ``stderr`` contendo
    "Operation not permitted", representando execução sem privilégios root.
    """
    resultado = MagicMock()
    resultado.returncode = 1
    resultado.stdout = ""
    resultado.stderr = "iptables: Operation not permitted"

    mock = MagicMock(return_value=resultado)
    monkeypatch.setattr("subprocess.run", mock)
    return mock


@pytest.fixture
def mock_subprocess_falha_comando(monkeypatch):
    """
    Mock de ``subprocess.run`` que simula comando não encontrado.

    Lança ``FileNotFoundError``, representando um ambiente onde
    o binário ``iptables`` não está instalado ou não está no PATH.
    """
    mock = MagicMock(side_effect=FileNotFoundError("iptables: No such file or directory"))
    monkeypatch.setattr("subprocess.run", mock)
    return mock


# =============================================================
# Fixtures de mock — HTTP (httpx)
# =============================================================

@pytest.fixture
def mock_httpx_sucesso(monkeypatch):
    """
    Mock de ``httpx.post`` que retorna resposta HTTP 200.

    Simula envio bem-sucedido de notificação para Slack, Telegram
    ou qualquer endpoint HTTP da camada de notificações.
    """
    resposta = MagicMock()
    resposta.status_code = 200
    resposta.text = "ok"

    mock = MagicMock(return_value=resposta)
    monkeypatch.setattr("httpx.post", mock)
    return mock


@pytest.fixture
def mock_httpx_falha(monkeypatch):
    """
    Mock de ``httpx.post`` que lança ``httpx.ConnectError``.

    Simula falha de conectividade ao tentar enviar notificação,
    representando canal de notificação indisponível.
    """
    import httpx

    mock = MagicMock(side_effect=httpx.ConnectError("Connection refused"))
    monkeypatch.setattr("httpx.post", mock)
    return mock


# =============================================================
# Fixtures de dados — IncidentReport
# =============================================================

@pytest.fixture
def incident_report_critico():
    """
    IncidentReport com score crítico (>= 80) para uso nos testes da Camada 5.

    Representa um incidente de brute force SSH com severidade CRITICO,
    incluindo ação de bloqueio de firewall nas recomendações.
    """
    from agent.report_generator import IncidentReport

    return IncidentReport(
        incident_id="INC-2025-0001",
        severidade="CRITICO",
        resumo=(
            "Ataque de força bruta SSH detectado originado de 203.0.113.5 "
            "com 847 tentativas em menos de 10 minutos."
        ),
        linha_do_tempo=[
            {
                "timestamp": "2025-01-15T10:00:00Z",
                "evento": "Início das tentativas de autenticação SSH",
                "significancia": "Primeiro evento do ataque detectado",
            },
            {
                "timestamp": "2025-01-15T10:08:00Z",
                "evento": "847 falhas de autenticação acumuladas",
                "significancia": "Volume anormal indica automação do ataque",
            },
        ],
        impacto_estimado=(
            "Risco de comprometimento de credenciais SSH. Acesso não autorizado "
            "pode resultar em exfiltração de dados ou instalação de malware."
        ),
        acoes_recomendadas=[
            "Bloquear IP 203.0.113.5 no firewall imediatamente",
            "Verificar logs de autenticação bem-sucedida do mesmo IP",
            "Revisar política de senhas e habilitar autenticação por chave SSH",
        ],
        tecnicas_mitre=["T1110"],
        confianca=0.95,
        timestamp_geracao=datetime.now(timezone.utc).isoformat(),
        raw_llm_response="",
    )


@pytest.fixture
def incident_report_alto():
    """
    IncidentReport com score alto (>= 60 e < 80) para uso nos testes da Camada 5.

    Representa um incidente de port scan com severidade ALTO, onde apenas
    notificações devem ser disparadas (sem bloqueio automático de firewall).
    """
    from agent.report_generator import IncidentReport

    return IncidentReport(
        incident_id="INC-2025-0002",
        severidade="ALTO",
        resumo=(
            "Varredura de portas detectada originada de 198.51.100.42 "
            "com 1500 conexões em 5 segundos."
        ),
        linha_do_tempo=[
            {
                "timestamp": "2025-01-15T11:00:00Z",
                "evento": "Início da varredura de portas",
                "significancia": "Reconhecimento de serviços ativos",
            },
        ],
        impacto_estimado=(
            "Possível reconhecimento de infraestrutura para ataque subsequente. "
            "Risco moderado de exposição de serviços vulneráveis."
        ),
        acoes_recomendadas=[
            "Monitorar atividade subsequente do IP 198.51.100.42",
            "Revisar regras de firewall para serviços expostos",
        ],
        tecnicas_mitre=["T1046"],
        confianca=0.78,
        timestamp_geracao=datetime.now(timezone.utc).isoformat(),
        raw_llm_response="",
    )
