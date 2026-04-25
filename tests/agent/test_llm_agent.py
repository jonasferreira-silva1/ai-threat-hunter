"""
Testes unitários para LLMAgent e ReportGenerator — AI-Powered Threat Hunter
============================================================================
Cobre:
    - investigar() com mock da API retornando resposta válida
    - investigar() com mock falhando 3 vezes → confianca=0.0
    - Formato do incident_id (regex INC-\\d{4}-\\d{4})
    - Ordenação cronológica da linha_do_tempo
    - acoes_recomendadas inclui bloqueio de firewall quando score >= 80
    - ReportGenerator: JSON inválido → confianca=0.0
    - ReportGenerator: fallbacks para campos ausentes
"""

import json
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from agent.context_builder import ThreatContext
from agent.llm_agent import LLMAgent
from agent.report_generator import IncidentReport, ReportGenerator, _contadores_por_ano

# Padrão esperado para incident_id
PATTERN_INCIDENT_ID = re.compile(r"^INC-\d{4}-\d{4}$")

# Resposta JSON válida simulando o LLM
RESPOSTA_JSON_VALIDA = json.dumps({
    "incident_id": "INC-2025-0001",
    "severidade": "CRITICO",
    "resumo": "Ataque de força bruta SSH detectado com 847 tentativas.",
    "linha_do_tempo": [
        {
            "timestamp": "2025-01-15T10:08:00Z",
            "evento": "847 falhas de autenticação acumuladas",
            "significancia": "Volume anormal indica automação",
        },
        {
            "timestamp": "2025-01-15T10:00:00Z",
            "evento": "Início das tentativas SSH",
            "significancia": "Primeiro evento detectado",
        },
    ],
    "impacto_estimado": "Risco de comprometimento de credenciais SSH.",
    "acoes_recomendadas": [
        "Bloquear IP 203.0.113.5 no firewall imediatamente",
        "Verificar logs de autenticação",
    ],
    "tecnicas_mitre": ["T1110"],
    "confianca": 0.95,
    "timestamp_geracao": "2025-01-15T10:09:00Z",
    "raw_llm_response": "",
})


# =============================================================
# Fixtures locais
# =============================================================

@pytest.fixture
def contexto_critico(resultado_score_critico, evento_brute_force):
    """ThreatContext com score crítico (>= 80)."""
    return ThreatContext(
        evento_id="test-001",
        evento_atual=evento_brute_force,
        score=resultado_score_critico,
        eventos_correlacionados=[],
        historico_ip=[],
        timestamp_inicio="2025-01-15T09:59:00+00:00",
        timestamp_fim="2025-01-15T10:09:00+00:00",
    )


@pytest.fixture
def contexto_com_timeline(resultado_score_critico, evento_brute_force):
    """ThreatContext com eventos correlacionados para testar ordenação."""
    eventos = [
        {"@timestamp": "2025-01-15T10:05:00Z", "event_type": "auth_failure"},
        {"@timestamp": "2025-01-15T10:01:00Z", "event_type": "auth_failure"},
        {"@timestamp": "2025-01-15T10:08:00Z", "event_type": "auth_failure"},
    ]
    return ThreatContext(
        evento_id="test-002",
        evento_atual=evento_brute_force,
        score=resultado_score_critico,
        eventos_correlacionados=eventos,
        historico_ip=[],
        timestamp_inicio="2025-01-15T09:59:00+00:00",
        timestamp_fim="2025-01-15T10:09:00+00:00",
    )


# =============================================================
# Testes do ReportGenerator
# =============================================================

class TestReportGenerator:
    """Testes unitários para a classe ReportGenerator."""

    def test_gerar_relatorio_valido(self, contexto_critico):
        """Deve parsear JSON válido e retornar IncidentReport completo."""
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, RESPOSTA_JSON_VALIDA)

        assert isinstance(report, IncidentReport)
        assert PATTERN_INCIDENT_ID.match(report.incident_id)
        assert report.severidade == "CRITICO"
        assert report.resumo
        assert report.confianca == 0.95
        assert isinstance(report.acoes_recomendadas, list)
        assert len(report.acoes_recomendadas) > 0

    def test_json_invalido_retorna_confianca_zero(self, contexto_critico):
        """JSON inválido deve retornar IncidentReport com confianca=0.0."""
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, "isso não é json {{{")

        assert report.confianca == 0.0
        assert "erro" in report.resumo.lower() or "parsear" in report.resumo.lower()
        assert PATTERN_INCIDENT_ID.match(report.incident_id)

    def test_acoes_recomendadas_nao_vazia_com_fallback(self, contexto_critico):
        """Deve usar fallback quando acoes_recomendadas está ausente ou vazia."""
        dados = json.loads(RESPOSTA_JSON_VALIDA)
        dados["acoes_recomendadas"] = []
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, json.dumps(dados))

        assert isinstance(report.acoes_recomendadas, list)
        assert len(report.acoes_recomendadas) > 0

    def test_impacto_estimado_nao_vazio_com_fallback(self, contexto_critico):
        """Deve usar fallback quando impacto_estimado está ausente ou vazio."""
        dados = json.loads(RESPOSTA_JSON_VALIDA)
        dados["impacto_estimado"] = ""
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, json.dumps(dados))

        assert report.impacto_estimado
        assert len(report.impacto_estimado) > 0

    def test_score_critico_inclui_acao_firewall(self, contexto_critico):
        """Para score >= 80, deve incluir ação de bloqueio de firewall."""
        dados = json.loads(RESPOSTA_JSON_VALIDA)
        dados["acoes_recomendadas"] = ["Verificar logs de autenticação"]
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, json.dumps(dados))

        acoes_lower = [a.lower() for a in report.acoes_recomendadas]
        tem_firewall = any(
            "firewall" in a or "bloquear" in a or "block" in a
            for a in acoes_lower
        )
        assert tem_firewall, f"Esperava ação de firewall, mas obteve: {report.acoes_recomendadas}"

    def test_score_nao_critico_nao_adiciona_firewall(self, resultado_score_alto, evento_brute_force):
        """Para score < 80, não deve adicionar ação de firewall automaticamente."""
        contexto = ThreatContext(
            evento_id="test-003",
            evento_atual=evento_brute_force,
            score=resultado_score_alto,
            eventos_correlacionados=[],
            historico_ip=[],
            timestamp_inicio="",
            timestamp_fim="",
        )
        dados = json.loads(RESPOSTA_JSON_VALIDA)
        dados["acoes_recomendadas"] = ["Verificar logs de autenticação"]
        generator = ReportGenerator()
        report = generator.gerar(contexto, json.dumps(dados))

        # Não deve ter adicionado firewall automaticamente
        assert report.acoes_recomendadas == ["Verificar logs de autenticação"]

    def test_timestamp_geracao_valido(self, contexto_critico):
        """timestamp_geracao deve ser ISO 8601 UTC válido."""
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, RESPOSTA_JSON_VALIDA)

        ts = report.timestamp_geracao.replace("Z", "+00:00")
        # Não deve lançar exceção
        dt = datetime.fromisoformat(ts)
        assert dt is not None

    def test_timestamp_invalido_usa_fallback(self, contexto_critico):
        """Timestamp inválido no JSON deve ser substituído pelo timestamp atual."""
        dados = json.loads(RESPOSTA_JSON_VALIDA)
        dados["timestamp_geracao"] = "data-invalida"
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, json.dumps(dados))

        # Deve ter substituído por timestamp válido
        ts = report.timestamp_geracao.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        assert dt is not None

    def test_json_em_markdown_code_block(self, contexto_critico):
        """Deve extrair JSON de dentro de blocos de código markdown."""
        resposta_com_markdown = f"```json\n{RESPOSTA_JSON_VALIDA}\n```"
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, resposta_com_markdown)

        assert report.confianca == 0.95
        assert report.severidade == "CRITICO"

    def test_incident_id_formato_correto(self, contexto_critico):
        """incident_id deve seguir o formato INC-YYYY-NNNN."""
        generator = ReportGenerator()
        report = generator.gerar(contexto_critico, RESPOSTA_JSON_VALIDA)

        assert PATTERN_INCIDENT_ID.match(report.incident_id), (
            f"incident_id '{report.incident_id}' não corresponde ao padrão INC-YYYY-NNNN"
        )

    def test_incident_id_sequencial(self, contexto_critico):
        """Dois relatórios gerados em sequência devem ter IDs diferentes."""
        generator = ReportGenerator()
        report1 = generator.gerar(contexto_critico, RESPOSTA_JSON_VALIDA)
        report2 = generator.gerar(contexto_critico, RESPOSTA_JSON_VALIDA)

        assert report1.incident_id != report2.incident_id


# =============================================================
# Testes do LLMAgent
# =============================================================

class TestLLMAgent:
    """Testes unitários para a classe LLMAgent."""

    def test_investigar_com_api_valida(
        self,
        mock_anthropic_client,
        contexto_critico,
    ):
        """investigar() com mock válido deve retornar IncidentReport completo."""
        # Configura o mock para retornar a resposta válida em ambas as chamadas
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        report = agent.investigar(contexto_critico)

        assert isinstance(report, IncidentReport)
        assert PATTERN_INCIDENT_ID.match(report.incident_id)
        assert report.confianca >= 0.0
        assert report.confianca <= 1.0

    def test_investigar_api_falha_3_vezes_retorna_confianca_zero(
        self,
        mock_anthropic_client_falha,
        contexto_critico,
    ):
        """investigar() com API falhando 3 vezes deve retornar confianca=0.0."""
        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client_falha
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        # Patch time.sleep para não esperar nos testes
        with patch("agent.llm_agent.time.sleep"):
            report = agent.investigar(contexto_critico)

        assert report.confianca == 0.0
        assert report.resumo  # Deve ter mensagem de erro
        assert PATTERN_INCIDENT_ID.match(report.incident_id)

    def test_investigar_nunca_lanca_excecao(
        self,
        mock_anthropic_client_falha,
        contexto_critico,
    ):
        """investigar() nunca deve lançar exceção, mesmo com API falhando."""
        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client_falha
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        with patch("agent.llm_agent.time.sleep"):
            # Não deve lançar exceção
            report = agent.investigar(contexto_critico)

        assert isinstance(report, IncidentReport)

    def test_incident_id_formato_correto(
        self,
        mock_anthropic_client,
        contexto_critico,
    ):
        """incident_id deve seguir o padrão INC-YYYY-NNNN."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        report = agent.investigar(contexto_critico)

        assert PATTERN_INCIDENT_ID.match(report.incident_id), (
            f"incident_id '{report.incident_id}' não corresponde ao padrão INC-YYYY-NNNN"
        )

    def test_linha_do_tempo_ordenada_cronologicamente(
        self,
        mock_anthropic_client,
        contexto_com_timeline,
    ):
        """linha_do_tempo deve estar ordenada por timestamp crescente."""
        # Resposta com eventos fora de ordem
        resposta_desordenada = json.dumps({
            "incident_id": "INC-2025-0001",
            "severidade": "CRITICO",
            "resumo": "Ataque detectado.",
            "linha_do_tempo": [
                {"timestamp": "2025-01-15T10:08:00Z", "evento": "Terceiro evento"},
                {"timestamp": "2025-01-15T10:01:00Z", "evento": "Primeiro evento"},
                {"timestamp": "2025-01-15T10:05:00Z", "evento": "Segundo evento"},
            ],
            "impacto_estimado": "Risco alto.",
            "acoes_recomendadas": ["Bloquear IP no firewall"],
            "tecnicas_mitre": ["T1110"],
            "confianca": 0.9,
            "timestamp_geracao": "2025-01-15T10:09:00Z",
            "raw_llm_response": "",
        })

        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=resposta_desordenada)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        report = agent.investigar(contexto_com_timeline)

        timestamps = [e["timestamp"] for e in report.linha_do_tempo]
        assert timestamps == sorted(timestamps), (
            f"linha_do_tempo não está ordenada: {timestamps}"
        )

    def test_acoes_recomendadas_inclui_firewall_para_score_critico(
        self,
        mock_anthropic_client,
        contexto_critico,
    ):
        """Para score >= 80, acoes_recomendadas deve incluir bloqueio de firewall."""
        # Resposta sem ação de firewall
        resposta_sem_firewall = json.dumps({
            "incident_id": "INC-2025-0001",
            "severidade": "CRITICO",
            "resumo": "Ataque detectado.",
            "linha_do_tempo": [
                {"timestamp": "2025-01-15T10:00:00Z", "evento": "Início do ataque"},
            ],
            "impacto_estimado": "Risco alto.",
            "acoes_recomendadas": ["Verificar logs de autenticação"],
            "tecnicas_mitre": ["T1110"],
            "confianca": 0.9,
            "timestamp_geracao": "2025-01-15T10:09:00Z",
            "raw_llm_response": "",
        })

        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=resposta_sem_firewall)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        report = agent.investigar(contexto_critico)

        acoes_lower = [a.lower() for a in report.acoes_recomendadas]
        tem_firewall = any(
            "firewall" in a or "bloquear" in a or "block" in a
            for a in acoes_lower
        )
        assert tem_firewall, (
            f"Esperava ação de firewall para score crítico, mas obteve: {report.acoes_recomendadas}"
        )

    def test_retry_chama_api_3_vezes(
        self,
        mock_anthropic_client_falha,
        contexto_critico,
    ):
        """Em caso de falha, deve tentar exatamente 3 vezes."""
        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client_falha
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        with patch("agent.llm_agent.time.sleep"):
            agent.investigar(contexto_critico)

        # Cada fase (investigação + relatório) tenta 3 vezes
        # A primeira fase falha em 3 tentativas e retorna erro
        assert mock_anthropic_client_falha.messages.create.call_count == 3

    def test_confianca_em_intervalo_valido(
        self,
        mock_anthropic_client,
        contexto_critico,
    ):
        """confianca deve estar sempre no intervalo [0.0, 1.0]."""
        mensagem_mock = MagicMock()
        mensagem_mock.content = [MagicMock(text=RESPOSTA_JSON_VALIDA)]
        mock_anthropic_client.messages.create.return_value = mensagem_mock

        agent = LLMAgent.__new__(LLMAgent)
        agent._model = "claude-3-5-sonnet-20241022"
        agent._client = mock_anthropic_client
        from agent.mitre_mapper import MITREMapper
        from agent.report_generator import ReportGenerator
        agent._mitre_mapper = MITREMapper()
        agent._report_generator = ReportGenerator()

        report = agent.investigar(contexto_critico)

        assert 0.0 <= report.confianca <= 1.0
