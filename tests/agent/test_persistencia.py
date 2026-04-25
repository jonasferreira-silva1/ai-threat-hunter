"""
Testes de integração (com mock do ES) para persistência — AI-Powered Threat Hunter
====================================================================================
Cobre:
    - persistir() chama es.index() com o índice correto ('incidents')
    - persistir() chama es.update() para marcar agent_analyzed=True
    - Falha do ES em index() retorna False sem lançar exceção
    - Falha do ES em update() retorna False sem lançar exceção
    - LLMAgent.investigar() chama persistir() quando es_client é fornecido
    - LLMAgent.investigar() não chama persistir() quando es_client é None

Requisitos: 6.1, 15.4
"""

import json
from unittest.mock import MagicMock, patch, call

import pytest

from agent.context_builder import ThreatContext
from agent.llm_agent import LLMAgent
from agent.mitre_mapper import MITREMapper
from agent.report_generator import IncidentReport, ReportGenerator


# =============================================================
# Fixtures locais
# =============================================================

RESPOSTA_JSON_VALIDA = json.dumps({
    "incident_id": "INC-2025-0001",
    "severidade": "CRITICO",
    "resumo": "Ataque de força bruta SSH detectado com 847 tentativas.",
    "linha_do_tempo": [
        {
            "timestamp": "2025-01-15T10:00:00Z",
            "evento": "Início das tentativas SSH",
            "significancia": "Primeiro evento detectado",
        },
    ],
    "impacto_estimado": "Risco de comprometimento de credenciais SSH.",
    "acoes_recomendadas": [
        "Bloquear IP 203.0.113.5 no firewall imediatamente",
    ],
    "tecnicas_mitre": ["T1110"],
    "confianca": 0.95,
    "timestamp_geracao": "2025-01-15T10:09:00Z",
    "raw_llm_response": "",
})


@pytest.fixture
def report_exemplo():
    """IncidentReport de exemplo para uso nos testes de persistência."""
    return IncidentReport(
        incident_id="INC-2025-TEST",
        severidade="CRITICO",
        resumo="Ataque de força bruta SSH detectado.",
        linha_do_tempo=[
            {
                "timestamp": "2025-01-15T10:00:00Z",
                "evento": "Início do ataque",
                "significancia": "Primeiro evento",
            }
        ],
        impacto_estimado="Risco de comprometimento de credenciais.",
        acoes_recomendadas=["Bloquear IP no firewall imediatamente"],
        tecnicas_mitre=["T1110"],
        confianca=0.95,
        timestamp_geracao="2025-01-15T10:09:00Z",
        raw_llm_response=RESPOSTA_JSON_VALIDA,
    )


@pytest.fixture
def contexto_critico(resultado_score_critico, evento_brute_force):
    """ThreatContext com score crítico para testes do LLMAgent."""
    return ThreatContext(
        evento_id="evt-brute-001",
        evento_atual=evento_brute_force,
        score=resultado_score_critico,
        eventos_correlacionados=[],
        historico_ip=[],
        timestamp_inicio="2025-01-15T09:59:00+00:00",
        timestamp_fim="2025-01-15T10:09:00+00:00",
    )


def _criar_agent(mock_client):
    """Cria um LLMAgent com mocks injetados diretamente (sem chamar __init__)."""
    agent = LLMAgent.__new__(LLMAgent)
    agent._model = "claude-3-5-sonnet-20241022"
    agent._client = mock_client
    agent._mitre_mapper = MITREMapper()
    agent._report_generator = ReportGenerator()
    return agent


# =============================================================
# Testes de ReportGenerator.persistir()
# =============================================================

class TestPersistir:
    """Testes unitários para ReportGenerator.persistir()."""

    def test_persistir_chama_index_com_indice_correto(
        self, report_exemplo, mock_es_client
    ):
        """persistir() deve chamar es.index() com index='incidents'."""
        generator = ReportGenerator()
        resultado = generator.persistir(report_exemplo, "evt-001", mock_es_client)

        assert resultado is True
        mock_es_client.index.assert_called_once()
        kwargs = mock_es_client.index.call_args
        # Aceita tanto args posicionais quanto keyword
        indice = kwargs.kwargs.get("index") or kwargs.args[0] if kwargs.args else None
        assert indice == "incidents" or mock_es_client.index.call_args[1].get("index") == "incidents"

    def test_persistir_usa_incident_id_como_document_id(
        self, report_exemplo, mock_es_client
    ):
        """persistir() deve usar incident_id como document ID no es.index()."""
        generator = ReportGenerator()
        generator.persistir(report_exemplo, "evt-001", mock_es_client)

        call_kwargs = mock_es_client.index.call_args[1]
        assert call_kwargs.get("id") == report_exemplo.incident_id

    def test_persistir_chama_update_com_agent_analyzed_true(
        self, report_exemplo, mock_es_client
    ):
        """persistir() deve chamar es.update() para marcar agent_analyzed=True."""
        generator = ReportGenerator()
        generator.persistir(report_exemplo, "evt-001", mock_es_client)

        mock_es_client.update.assert_called_once()
        call_kwargs = mock_es_client.update.call_args[1]
        assert call_kwargs.get("id") == "evt-001"
        assert call_kwargs["body"]["doc"]["agent_analyzed"] is True

    def test_persistir_falha_no_index_retorna_false(
        self, report_exemplo, mock_es_client_indisponivel
    ):
        """Falha no es.index() deve retornar False sem lançar exceção."""
        generator = ReportGenerator()
        resultado = generator.persistir(
            report_exemplo, "evt-001", mock_es_client_indisponivel
        )

        assert resultado is False

    def test_persistir_falha_no_update_retorna_false(
        self, report_exemplo, mock_es_client
    ):
        """Falha no es.update() deve retornar False sem lançar exceção."""
        mock_es_client.update.side_effect = ConnectionError("ES indisponível")
        generator = ReportGenerator()
        resultado = generator.persistir(report_exemplo, "evt-001", mock_es_client)

        assert resultado is False

    def test_persistir_sucesso_retorna_true(
        self, report_exemplo, mock_es_client
    ):
        """persistir() deve retornar True quando ambas as operações têm sucesso."""
        generator = ReportGenerator()
        resultado = generator.persistir(report_exemplo, "evt-001", mock_es_client)

        assert resultado is True

    def test_persistir_nao_lanca_excecao_em_falha(
        self, report_exemplo, mock_es_client_indisponivel
    ):
        """persistir() nunca deve lançar exceção, mesmo com ES indisponível."""
        generator = ReportGenerator()
        # Não deve lançar exceção
        resultado = generator.persistir(
            report_exemplo, "evt-001", mock_es_client_indisponivel
        )
        assert isinstance(resultado, bool)


# =============================================================
# Testes de LLMAgent.investigar() com es_client
# =============================================================

class TestInvestigarComPersistencia:
    """Testes para LLMAgent.investigar() com e sem es_client."""

    def test_investigar_chama_persistir_quando_es_client_fornecido(
        self, mock_anthropic_client, contexto_critico, mock_es_client
    ):
        """investigar() deve chamar persistir() quando es_client é fornecido."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = _criar_agent(mock_anthropic_client)

        # Espiona o método persistir
        agent._report_generator.persistir = MagicMock(return_value=True)

        agent.investigar(contexto_critico, es_client=mock_es_client)

        agent._report_generator.persistir.assert_called_once()
        call_args = agent._report_generator.persistir.call_args
        # Primeiro argumento: IncidentReport
        assert isinstance(call_args[0][0], IncidentReport)
        # Segundo argumento: evento_id
        assert call_args[0][1] == contexto_critico.evento_id
        # Terceiro argumento: es_client
        assert call_args[0][2] is mock_es_client

    def test_investigar_nao_chama_persistir_quando_es_client_none(
        self, mock_anthropic_client, contexto_critico
    ):
        """investigar() não deve chamar persistir() quando es_client é None."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = _criar_agent(mock_anthropic_client)
        agent._report_generator.persistir = MagicMock(return_value=True)

        agent.investigar(contexto_critico)  # sem es_client

        agent._report_generator.persistir.assert_not_called()

    def test_investigar_retorna_report_mesmo_com_es_client(
        self, mock_anthropic_client, contexto_critico, mock_es_client
    ):
        """investigar() deve retornar IncidentReport mesmo quando es_client é fornecido."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = _criar_agent(mock_anthropic_client)

        report = agent.investigar(contexto_critico, es_client=mock_es_client)

        assert isinstance(report, IncidentReport)
        assert report.confianca >= 0.0

    def test_investigar_retorna_report_sem_es_client(
        self, mock_anthropic_client, contexto_critico
    ):
        """investigar() deve retornar IncidentReport quando es_client não é fornecido."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = _criar_agent(mock_anthropic_client)

        report = agent.investigar(contexto_critico)

        assert isinstance(report, IncidentReport)
        assert report.confianca >= 0.0
