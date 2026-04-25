"""
Property-Based Tests para LLMAgent e ReportGenerator — AI-Powered Threat Hunter
================================================================================
Propriedades implementadas:
    - Property 9:  LLMAgent sempre retorna IncidentReport estruturalmente válido
    - Property 10: LLMAgent é resiliente a falhas da API LLM
    - Property 12: ReportGenerator produz relatórios completos e válidos
    - Property 13: ReportGenerator inclui ação de firewall para incidentes críticos

Biblioteca: hypothesis
"""

import json
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st

from agent.context_builder import ThreatContext
from agent.llm_agent import LLMAgent
from agent.report_generator import IncidentReport, ReportGenerator

# Padrão esperado para incident_id
PATTERN_INCIDENT_ID = re.compile(r"^INC-\d{4}-\d{4}$")

# Palavras-chave de firewall
PALAVRAS_FIREWALL = ("firewall", "bloquear", "block", "iptables", "nftables", "drop")


# =============================================================
# Estratégias (generators) para Hypothesis
# =============================================================

def _make_resultado_score(score: float):
    """Cria um ResultadoScore simulado com o score fornecido."""
    from ml.scorer import ResultadoScore
    return ResultadoScore(
        score=score,
        severidade="CRITICO" if score >= 80 else "ALTO" if score >= 60 else "MEDIO",
        score_anomalia=min(score / 100.0, 1.0),
        is_anomalo=score >= 60,
        classe_ameaca="BRUTE_FORCE",
        probabilidades={"BRUTE_FORCE": 0.9, "NORMAL": 0.1},
        evento_id="prop-test",
        requer_resposta_automatica=score >= 80,
        requer_investigacao_llm=score >= 60,
    )


@st.composite
def threat_context_strategy(draw):
    """Gera ThreatContext válidos com scores variados."""
    score_valor = draw(st.floats(min_value=0.0, max_value=100.0, allow_nan=False))
    score = _make_resultado_score(score_valor)

    evento = {
        "_id": draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")))),
        "event_type": draw(st.sampled_from(["auth_failure", "network_connection", "http_request"])),
        "source_ip": draw(st.from_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", fullmatch=True)),
        "@timestamp": "2025-01-15T10:00:00Z",
        "count": draw(st.integers(min_value=0, max_value=10000)),
    }

    return ThreatContext(
        evento_id=evento["_id"],
        evento_atual=evento,
        score=score,
        eventos_correlacionados=[],
        historico_ip=[],
        timestamp_inicio="2025-01-15T09:50:00+00:00",
        timestamp_fim="2025-01-15T10:00:00+00:00",
    )


@st.composite
def resposta_llm_valida_strategy(draw):
    """Gera respostas JSON válidas simulando o LLM."""
    confianca = draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
    severidade = draw(st.sampled_from(["CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"]))
    resumo = draw(st.text(min_size=10, max_size=200, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs", "Po"))))
    impacto = draw(st.text(min_size=10, max_size=200, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs", "Po"))))

    n_acoes = draw(st.integers(min_value=1, max_value=5))
    acoes = [
        draw(st.text(min_size=5, max_size=100, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs", "Po"))))
        for _ in range(n_acoes)
    ]

    return json.dumps({
        "incident_id": "INC-2025-0001",
        "severidade": severidade,
        "resumo": resumo or "Incidente detectado.",
        "linha_do_tempo": [
            {
                "timestamp": "2025-01-15T10:00:00Z",
                "evento": "Evento detectado",
                "significancia": "Relevante",
            }
        ],
        "impacto_estimado": impacto or "Impacto desconhecido.",
        "acoes_recomendadas": acoes,
        "tecnicas_mitre": ["T1110"],
        "confianca": confianca,
        "timestamp_geracao": "2025-01-15T10:09:00Z",
        "raw_llm_response": "",
    })


@st.composite
def score_critico_strategy(draw):
    """Gera scores críticos (>= 80)."""
    return draw(st.floats(min_value=80.0, max_value=100.0, allow_nan=False))


# =============================================================
# Property 9: LLMAgent sempre retorna IncidentReport estruturalmente válido
# =============================================================

@given(contexto=threat_context_strategy())
@settings(max_examples=30, deadline=10000)
def test_property_9_llm_agent_retorna_incident_report_valido(contexto):
    """
    **Validates: Requirements 5.1, 5.2, 5.3**

    Property 9: LLMAgent sempre retorna IncidentReport estruturalmente válido.

    Para qualquer ThreatContext válido (com LLM mockado), investigar() deve
    retornar um IncidentReport onde:
    - incident_id corresponde ao formato INC-YYYY-NNNN
    - confianca está em [0.0, 1.0]
    - resumo, linha_do_tempo e tecnicas_mitre são não-nulos
    """
    resposta_valida = json.dumps({
        "incident_id": "INC-2025-0001",
        "severidade": "ALTO",
        "resumo": "Incidente detectado pelo sistema.",
        "linha_do_tempo": [
            {"timestamp": "2025-01-15T10:00:00Z", "evento": "Evento", "significancia": "Relevante"}
        ],
        "impacto_estimado": "Impacto potencial nos sistemas.",
        "acoes_recomendadas": ["Revisar logs", "Bloquear IP no firewall"],
        "tecnicas_mitre": ["T1110"],
        "confianca": 0.85,
        "timestamp_geracao": "2025-01-15T10:09:00Z",
        "raw_llm_response": "",
    })

    mensagem_mock = MagicMock()
    mensagem_mock.content = [MagicMock(text=resposta_valida)]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mensagem_mock

    agent = LLMAgent.__new__(LLMAgent)
    agent._model = "claude-3-5-sonnet-20241022"
    agent._client = mock_client
    from agent.mitre_mapper import MITREMapper
    from agent.report_generator import ReportGenerator
    agent._mitre_mapper = MITREMapper()
    agent._report_generator = ReportGenerator()

    report = agent.investigar(contexto)

    # Verifica estrutura obrigatória
    assert isinstance(report, IncidentReport)
    assert PATTERN_INCIDENT_ID.match(report.incident_id), (
        f"incident_id '{report.incident_id}' não corresponde ao padrão INC-YYYY-NNNN"
    )
    assert 0.0 <= report.confianca <= 1.0, (
        f"confianca={report.confianca} fora do intervalo [0.0, 1.0]"
    )
    assert report.resumo is not None
    assert report.linha_do_tempo is not None
    assert report.tecnicas_mitre is not None


# =============================================================
# Property 10: LLMAgent é resiliente a falhas da API LLM
# =============================================================

@given(contexto=threat_context_strategy())
@settings(max_examples=20, deadline=10000)
def test_property_10_llm_agent_resiliente_a_falhas(contexto):
    """
    **Validates: Requirements 5.4**

    Property 10: LLMAgent é resiliente a falhas da API LLM.

    Para qualquer ThreatContext válido, se a API do LLM falhar em todas as
    3 tentativas, investigar() deve retornar um IncidentReport com
    confianca=0.0 sem lançar exceção.
    """
    import anthropic

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = anthropic.APIConnectionError(
        request=MagicMock()
    )

    agent = LLMAgent.__new__(LLMAgent)
    agent._model = "claude-3-5-sonnet-20241022"
    agent._client = mock_client
    from agent.mitre_mapper import MITREMapper
    from agent.report_generator import ReportGenerator
    agent._mitre_mapper = MITREMapper()
    agent._report_generator = ReportGenerator()

    with patch("agent.llm_agent.time.sleep"):
        # Não deve lançar exceção
        report = agent.investigar(contexto)

    assert isinstance(report, IncidentReport), (
        "investigar() deve sempre retornar IncidentReport"
    )
    assert report.confianca == 0.0, (
        f"confianca deve ser 0.0 em caso de falha total, mas foi {report.confianca}"
    )
    assert PATTERN_INCIDENT_ID.match(report.incident_id)


# =============================================================
# Property 12: ReportGenerator produz relatórios completos e válidos
# =============================================================

@given(
    contexto=threat_context_strategy(),
    resposta_llm=resposta_llm_valida_strategy(),
)
@settings(max_examples=30, deadline=5000)
def test_property_12_report_generator_relatorios_completos(contexto, resposta_llm):
    """
    **Validates: Requirements 6.2, 6.3, 6.5**

    Property 12: ReportGenerator produz relatórios completos e válidos.

    Para qualquer IncidentReport gerado, os campos:
    - acoes_recomendadas: lista não-vazia
    - impacto_estimado: string não-vazia
    - timestamp_geracao: ISO 8601 UTC válido
    devem estar presentes e corretos.
    """
    generator = ReportGenerator()
    report = generator.gerar(contexto, resposta_llm)

    # acoes_recomendadas deve ser lista não-vazia
    assert isinstance(report.acoes_recomendadas, list), (
        "acoes_recomendadas deve ser uma lista"
    )
    assert len(report.acoes_recomendadas) > 0, (
        "acoes_recomendadas não deve ser vazia"
    )

    # impacto_estimado deve ser string não-vazia
    assert isinstance(report.impacto_estimado, str), (
        "impacto_estimado deve ser uma string"
    )
    assert len(report.impacto_estimado.strip()) > 0, (
        "impacto_estimado não deve ser vazia"
    )

    # timestamp_geracao deve ser ISO 8601 UTC válido
    ts = report.timestamp_geracao.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
        assert dt is not None
    except ValueError as exc:
        raise AssertionError(
            f"timestamp_geracao '{report.timestamp_geracao}' não é ISO 8601 válido: {exc}"
        )


# =============================================================
# Property 13: ReportGenerator inclui ação de firewall para incidentes críticos
# =============================================================

@given(score_critico=score_critico_strategy())
@settings(max_examples=30, deadline=5000)
def test_property_13_report_generator_firewall_para_criticos(score_critico):
    """
    **Validates: Requirements 6.4**

    Property 13: ReportGenerator inclui ação de firewall para incidentes críticos.

    Para qualquer IncidentReport gerado com score >= 80, a lista
    acoes_recomendadas deve conter pelo menos uma ação de bloqueio de firewall.
    """
    score = _make_resultado_score(score_critico)
    contexto = ThreatContext(
        evento_id="prop-test-13",
        evento_atual={"_id": "evt-001", "source_ip": "10.0.0.1", "event_type": "auth_failure"},
        score=score,
        eventos_correlacionados=[],
        historico_ip=[],
        timestamp_inicio="2025-01-15T09:50:00+00:00",
        timestamp_fim="2025-01-15T10:00:00+00:00",
    )

    # Resposta sem ação de firewall — o generator deve adicionar
    resposta_sem_firewall = json.dumps({
        "incident_id": "INC-2025-0001",
        "severidade": "CRITICO",
        "resumo": "Incidente crítico detectado.",
        "linha_do_tempo": [
            {"timestamp": "2025-01-15T10:00:00Z", "evento": "Evento", "significancia": "Relevante"}
        ],
        "impacto_estimado": "Impacto crítico nos sistemas.",
        "acoes_recomendadas": ["Verificar logs de autenticação"],
        "tecnicas_mitre": ["T1110"],
        "confianca": 0.9,
        "timestamp_geracao": "2025-01-15T10:09:00Z",
        "raw_llm_response": "",
    })

    generator = ReportGenerator()
    report = generator.gerar(contexto, resposta_sem_firewall)

    acoes_lower = [a.lower() for a in report.acoes_recomendadas]
    tem_firewall = any(
        any(palavra in acao for palavra in PALAVRAS_FIREWALL)
        for acao in acoes_lower
    )

    assert tem_firewall, (
        f"Para score={score_critico} (>= 80), esperava ação de firewall, "
        f"mas obteve: {report.acoes_recomendadas}"
    )
