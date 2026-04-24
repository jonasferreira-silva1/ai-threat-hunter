"""
Fixtures compartilhadas para os testes da Camada 4 — Agente LLM.

Fornece mocks do cliente Elasticsearch e da API LLM (Anthropic/OpenAI)
para que os testes sejam executados sem dependências externas.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field


# =============================================================
# Fixtures de dados — ThreatContext e ResultadoScore
# =============================================================

@pytest.fixture
def resultado_score_critico():
    """ResultadoScore simulando um incidente crítico (score >= 80)."""
    from ml.scorer import ResultadoScore
    return ResultadoScore(
        score=87.0,
        severidade="CRITICO",
        score_anomalia=0.94,
        is_anomalo=True,
        classe_ameaca="BRUTE_FORCE",
        probabilidades={"BRUTE_FORCE": 0.91, "NORMAL": 0.05, "PORT_SCAN": 0.04},
        evento_id="test-001",
        requer_resposta_automatica=True,
        requer_investigacao_llm=True,
    )


@pytest.fixture
def resultado_score_alto():
    """ResultadoScore simulando um incidente alto (60 <= score < 80)."""
    from ml.scorer import ResultadoScore
    return ResultadoScore(
        score=65.0,
        severidade="ALTO",
        score_anomalia=0.72,
        is_anomalo=True,
        classe_ameaca="PORT_SCAN",
        probabilidades={"PORT_SCAN": 0.78, "NORMAL": 0.15, "BRUTE_FORCE": 0.07},
        evento_id="test-002",
        requer_resposta_automatica=False,
        requer_investigacao_llm=True,
    )


@pytest.fixture
def evento_brute_force():
    """Evento de brute force SSH para uso nos testes do agente."""
    return {
        "_id": "evt-brute-001",
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "auth_failure",
        "source_ip": "203.0.113.5",
        "username": "root",
        "count": 847,
        "category": "authentication",
        "protocol": "TCP",
        "bytes_sent": 0,
        "bytes_received": 0,
        "duration_ms": 0.0,
        "http_status": 0,
        "severity": "high",
        "ml_score": 87.0,
    }


@pytest.fixture
def evento_port_scan():
    """Evento de port scan para uso nos testes do agente."""
    return {
        "_id": "evt-scan-001",
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_connection",
        "source_ip": "198.51.100.42",
        "count": 1500,
        "category": "network",
        "protocol": "TCP",
        "bytes_sent": 512,
        "bytes_received": 0,
        "duration_ms": 5000.0,
        "http_status": 0,
        "severity": "high",
        "ml_score": 65.0,
    }


@pytest.fixture
def eventos_correlacionados_brute_force():
    """Lista de eventos correlacionados simulando histórico de brute force."""
    agora = datetime.now(timezone.utc)
    return [
        {
            "_id": f"corr-{i:03d}",
            "@timestamp": agora.isoformat(),
            "event_type": "auth_failure",
            "source_ip": "203.0.113.5",
            "username": "root",
            "count": 100 + i * 50,
            "category": "authentication",
        }
        for i in range(3)
    ]


# =============================================================
# Mock do cliente Elasticsearch
# =============================================================

@pytest.fixture
def mock_es_client():
    """
    Mock do cliente Elasticsearch (elasticsearch-py).

    Simula respostas de busca com estrutura compatível com a API real.
    Por padrão, retorna listas vazias — sobrescreva `search.return_value`
    nos testes que precisam de dados específicos.
    """
    cliente = MagicMock()

    # Resposta padrão de search: sem resultados
    cliente.search.return_value = {
        "hits": {
            "total": {"value": 0},
            "hits": [],
        }
    }

    # Resposta padrão de index: sucesso
    cliente.index.return_value = {
        "result": "created",
        "_id": "mock-incident-id",
    }

    # Resposta padrão de update: sucesso
    cliente.update.return_value = {
        "result": "updated",
    }

    return cliente


@pytest.fixture
def mock_es_client_com_eventos(
    mock_es_client,
    eventos_correlacionados_brute_force,
):
    """
    Mock do Elasticsearch pré-configurado com eventos de brute force.

    Retorna eventos correlacionados na primeira chamada a search()
    e histórico vazio na segunda.
    """
    mock_es_client.search.side_effect = [
        # Primeira chamada: eventos correlacionados (últimos 10 min)
        {
            "hits": {
                "total": {"value": len(eventos_correlacionados_brute_force)},
                "hits": [
                    {"_source": ev} for ev in eventos_correlacionados_brute_force
                ],
            }
        },
        # Segunda chamada: histórico do IP (últimos 30 dias)
        {
            "hits": {
                "total": {"value": len(eventos_correlacionados_brute_force)},
                "hits": [
                    {"_source": ev} for ev in eventos_correlacionados_brute_force
                ],
            }
        },
    ]
    return mock_es_client


@pytest.fixture
def mock_es_client_indisponivel():
    """
    Mock do Elasticsearch que lança ConnectionError em qualquer operação.

    Usado para testar resiliência do ContextBuilder quando o ES está fora.
    """
    cliente = MagicMock()
    # Usa ConnectionError genérico para não depender do pacote elasticsearch
    cliente.search.side_effect = ConnectionError("Elasticsearch indisponível")
    cliente.index.side_effect = ConnectionError("Elasticsearch indisponível")
    cliente.update.side_effect = ConnectionError("Elasticsearch indisponível")
    return cliente


# =============================================================
# Mock da API LLM (Anthropic / OpenAI)
# =============================================================

RESPOSTA_LLM_VALIDA = """{
  "incident_id": "INC-2025-0001",
  "severidade": "CRITICO",
  "resumo": "Ataque de força bruta SSH detectado originado de 203.0.113.5 com 847 tentativas em menos de 10 minutos.",
  "linha_do_tempo": [
    {
      "timestamp": "2025-01-15T10:00:00Z",
      "evento": "Início das tentativas de autenticação SSH",
      "significancia": "Primeiro evento do ataque detectado"
    },
    {
      "timestamp": "2025-01-15T10:08:00Z",
      "evento": "847 falhas de autenticação acumuladas",
      "significancia": "Volume anormal indica automação do ataque"
    }
  ],
  "impacto_estimado": "Risco de comprometimento de credenciais SSH. Acesso não autorizado ao servidor pode resultar em exfiltração de dados ou instalação de malware.",
  "acoes_recomendadas": [
    "Bloquear IP 203.0.113.5 no firewall imediatamente",
    "Verificar logs de autenticação bem-sucedida do mesmo IP",
    "Revisar política de senhas e habilitar autenticação por chave SSH",
    "Considerar implementação de fail2ban ou similar"
  ],
  "tecnicas_mitre": ["T1110"],
  "confianca": 0.95,
  "timestamp_geracao": "2025-01-15T10:09:00Z",
  "raw_llm_response": ""
}"""


@pytest.fixture
def mock_anthropic_client():
    """
    Mock do cliente Anthropic (claude-3-5-sonnet-20241022).

    Simula resposta bem-sucedida com JSON de IncidentReport válido.
    """
    cliente = MagicMock()

    # Simula estrutura de resposta da API Anthropic
    mensagem_mock = MagicMock()
    mensagem_mock.content = [MagicMock(text=RESPOSTA_LLM_VALIDA)]
    mensagem_mock.stop_reason = "end_turn"

    cliente.messages.create.return_value = mensagem_mock
    return cliente


@pytest.fixture
def mock_anthropic_client_falha():
    """
    Mock do cliente Anthropic que falha em todas as tentativas.

    Usado para testar resiliência do LLMAgent (deve retornar
    IncidentReport com confianca=0.0 sem lançar exceção).
    """
    import anthropic

    cliente = MagicMock()
    cliente.messages.create.side_effect = anthropic.APIConnectionError(
        request=MagicMock()
    )
    return cliente


@pytest.fixture
def mock_openai_client():
    """
    Mock do cliente OpenAI (gpt-4 como alternativa ao Claude).

    Simula resposta bem-sucedida com JSON de IncidentReport válido.
    """
    cliente = MagicMock()

    # Simula estrutura de resposta da API OpenAI
    escolha_mock = MagicMock()
    escolha_mock.message.content = RESPOSTA_LLM_VALIDA
    escolha_mock.finish_reason = "stop"

    resposta_mock = MagicMock()
    resposta_mock.choices = [escolha_mock]

    cliente.chat.completions.create.return_value = resposta_mock
    return cliente


@pytest.fixture
def mock_openai_client_falha():
    """
    Mock do cliente OpenAI que falha em todas as tentativas.
    """
    import openai

    cliente = MagicMock()
    cliente.chat.completions.create.side_effect = openai.APIConnectionError(
        request=MagicMock()
    )
    return cliente
