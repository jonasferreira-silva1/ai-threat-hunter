"""
Testes para ContextBuilder — AI-Powered Threat Hunter
======================================================
Cobre os requisitos 3.1 a 3.5:
    - Busca de eventos correlacionados (últimos 10 min do mesmo source_ip)
    - Busca de histórico do source_ip (últimos 30 dias)
    - Resiliência a falhas do Elasticsearch (ConnectionError, timeout)
    - Evento sem campo source_ip retorna contexto com listas vazias

Inclui testes unitários (task 3.2) e property-based test (task 3.3).
"""

import pytest
from unittest.mock import MagicMock
from hypothesis import given, settings
from hypothesis import strategies as st

from agent.context_builder import ContextBuilder, ThreatContext


# =============================================================
# Testes unitários — task 3.2
# =============================================================

class TestContextBuilderBuscaComEventos:
    """Valida busca com ES mockado retornando eventos."""

    @pytest.mark.unit
    def test_retorna_threat_context(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """construir() sempre retorna uma instância de ThreatContext."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert isinstance(contexto, ThreatContext)

    @pytest.mark.unit
    def test_eventos_correlacionados_preenchidos(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.1: eventos_correlacionados contém os eventos retornados pelo ES."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert len(contexto.eventos_correlacionados) == 3

    @pytest.mark.unit
    def test_historico_ip_preenchido(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.2: historico_ip contém os eventos retornados pelo ES."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert len(contexto.historico_ip) == 3

    @pytest.mark.unit
    def test_evento_atual_preservado(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """O evento original é preservado no ThreatContext."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.evento_atual is evento_brute_force

    @pytest.mark.unit
    def test_score_preservado(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """O ResultadoScore é preservado no ThreatContext."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.score is resultado_score_critico

    @pytest.mark.unit
    def test_timestamps_preenchidos(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """timestamp_inicio e timestamp_fim são strings não-vazias."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.timestamp_inicio != ""
        assert contexto.timestamp_fim != ""

    @pytest.mark.unit
    def test_es_search_chamado_duas_vezes(
        self, mock_es_client_com_eventos, evento_brute_force, resultado_score_critico
    ):
        """ES.search() é chamado exatamente 2 vezes: correlacionados + histórico."""
        builder = ContextBuilder(mock_es_client_com_eventos)
        builder.construir(evento_brute_force, resultado_score_critico)
        assert mock_es_client_com_eventos.search.call_count == 2

    @pytest.mark.unit
    def test_timeout_aplicado_nas_queries(
        self, mock_es_client, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.4: timeout de 2s é passado em todas as chamadas ao ES."""
        builder = ContextBuilder(mock_es_client)
        builder.construir(evento_brute_force, resultado_score_critico)
        for call in mock_es_client.search.call_args_list:
            kwargs = call.kwargs if call.kwargs else call[1]
            assert kwargs.get("request_timeout") == 2


class TestContextBuilderFallbackESIndisponivel:
    """Valida resiliência quando o Elasticsearch está indisponível."""

    @pytest.mark.unit
    def test_retorna_threat_context_sem_excecao(
        self, mock_es_client_indisponivel, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.3: ConnectionError não propaga — retorna ThreatContext."""
        builder = ContextBuilder(mock_es_client_indisponivel)
        # Não deve lançar exceção
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert isinstance(contexto, ThreatContext)

    @pytest.mark.unit
    def test_eventos_correlacionados_vazios_com_es_indisponivel(
        self, mock_es_client_indisponivel, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.3: eventos_correlacionados é [] quando ES falha."""
        builder = ContextBuilder(mock_es_client_indisponivel)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.eventos_correlacionados == []

    @pytest.mark.unit
    def test_historico_ip_vazio_com_es_indisponivel(
        self, mock_es_client_indisponivel, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.3: historico_ip é [] quando ES falha."""
        builder = ContextBuilder(mock_es_client_indisponivel)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.historico_ip == []

    @pytest.mark.unit
    def test_fallback_com_timeout_error(
        self, evento_brute_force, resultado_score_critico
    ):
        """Requisito 3.3: TimeoutError também resulta em listas vazias sem exceção."""
        es_timeout = MagicMock()
        es_timeout.search.side_effect = TimeoutError("ES timeout")
        builder = ContextBuilder(es_timeout)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.eventos_correlacionados == []
        assert contexto.historico_ip == []

    @pytest.mark.unit
    def test_fallback_com_exception_generica(
        self, evento_brute_force, resultado_score_critico
    ):
        """Qualquer exceção do ES resulta em listas vazias sem propagar."""
        es_falho = MagicMock()
        es_falho.search.side_effect = RuntimeError("Erro inesperado")
        builder = ContextBuilder(es_falho)
        contexto = builder.construir(evento_brute_force, resultado_score_critico)
        assert contexto.eventos_correlacionados == []
        assert contexto.historico_ip == []


class TestContextBuilderSemSourceIP:
    """Valida comportamento quando o evento não possui campo source_ip."""

    @pytest.mark.unit
    def test_retorna_threat_context_sem_source_ip(
        self, mock_es_client, resultado_score_critico
    ):
        """Requisito 3.5: evento sem source_ip retorna ThreatContext sem exceção."""
        evento_sem_ip = {"_id": "evt-sem-ip", "event_type": "auth_failure"}
        builder = ContextBuilder(mock_es_client)
        contexto = builder.construir(evento_sem_ip, resultado_score_critico)
        assert isinstance(contexto, ThreatContext)

    @pytest.mark.unit
    def test_listas_vazias_sem_source_ip(
        self, mock_es_client, resultado_score_critico
    ):
        """Requisito 3.5: listas de correlação e histórico são vazias sem source_ip."""
        evento_sem_ip = {"_id": "evt-sem-ip", "event_type": "auth_failure"}
        builder = ContextBuilder(mock_es_client)
        contexto = builder.construir(evento_sem_ip, resultado_score_critico)
        assert contexto.eventos_correlacionados == []
        assert contexto.historico_ip == []

    @pytest.mark.unit
    def test_es_nao_e_consultado_sem_source_ip(
        self, mock_es_client, resultado_score_critico
    ):
        """Sem source_ip, o ES não deve ser consultado."""
        evento_sem_ip = {"_id": "evt-sem-ip", "event_type": "auth_failure"}
        builder = ContextBuilder(mock_es_client)
        builder.construir(evento_sem_ip, resultado_score_critico)
        mock_es_client.search.assert_not_called()

    @pytest.mark.unit
    def test_source_ip_vazio_equivale_a_ausente(
        self, mock_es_client, resultado_score_critico
    ):
        """source_ip vazio ("") é tratado como ausente — listas vazias."""
        evento_ip_vazio = {"_id": "evt-ip-vazio", "source_ip": ""}
        builder = ContextBuilder(mock_es_client)
        contexto = builder.construir(evento_ip_vazio, resultado_score_critico)
        assert contexto.eventos_correlacionados == []
        assert contexto.historico_ip == []


# =============================================================
# Property-based test — task 3.3
# **Validates: Requirements 3.3**
# =============================================================

def _gerar_ipv4():
    """Gera endereços IPv4 válidos de forma eficiente."""
    octeto = st.integers(min_value=0, max_value=255)
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        octeto, octeto, octeto, octeto,
    )


# Estratégia para gerar eventos arbitrários com source_ip
_st_evento = st.fixed_dictionaries({
    "_id": st.text(min_size=1, max_size=50),
    "source_ip": _gerar_ipv4(),
    "event_type": st.sampled_from(["auth_failure", "auth_success", "network_connection"]),
})

# Estratégia para gerar eventos sem source_ip
_st_evento_sem_ip = st.fixed_dictionaries({
    "_id": st.text(min_size=1, max_size=50),
    "event_type": st.sampled_from(["auth_failure", "auth_success", "network_connection"]),
})


@given(evento=_st_evento | _st_evento_sem_ip)
@settings(max_examples=100)
def test_property_resiliente_a_es_indisponivel(evento):
    """
    **Validates: Requirements 3.3**

    Property 7: ContextBuilder é resiliente a falhas do Elasticsearch.

    Para qualquer evento (com ou sem source_ip) e ES indisponível,
    `construir()` deve retornar ThreatContext com listas vazias sem lançar exceção.
    """
    from ml.scorer import ResultadoScore

    es_indisponivel = MagicMock()
    es_indisponivel.search.side_effect = ConnectionError("ES indisponível")

    score = ResultadoScore(
        score=87.0,
        severidade="CRITICO",
        score_anomalia=0.94,
        is_anomalo=True,
        classe_ameaca="BRUTE_FORCE",
        probabilidades={"BRUTE_FORCE": 0.91},
        evento_id=evento.get("_id", ""),
        requer_resposta_automatica=True,
        requer_investigacao_llm=True,
    )

    builder = ContextBuilder(es_indisponivel)

    # Não deve lançar exceção
    contexto = builder.construir(evento, score)

    assert isinstance(contexto, ThreatContext), (
        f"Esperado ThreatContext, obtido {type(contexto)}"
    )
    assert contexto.eventos_correlacionados == [], (
        f"Esperado [] para eventos_correlacionados, obtido {contexto.eventos_correlacionados}"
    )
    assert contexto.historico_ip == [], (
        f"Esperado [] para historico_ip, obtido {contexto.historico_ip}"
    )
