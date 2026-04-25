"""
ContextBuilder — AI-Powered Threat Hunter
==========================================
Responsabilidade:
    Buscar e agregar contexto histórico no Elasticsearch para enriquecer
    alertas de segurança antes de enviá-los ao agente LLM.

    Para cada evento com score >= 60, o ContextBuilder:
    - Busca eventos correlacionados do mesmo source_ip nos últimos 10 minutos
    - Busca o histórico completo do source_ip nos últimos 30 dias
    - Retorna um ThreatContext com listas vazias em caso de falha do ES

Requisitos: 3.1, 3.2, 3.3, 3.4, 3.5
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("threat-hunter.agent.context_builder")

# Timeouts e limites de busca
_TIMEOUT_ES_SEGUNDOS = 2
_SIZE_CORRELACIONADOS = 50
_SIZE_HISTORICO = 100
_JANELA_CORRELACAO_MINUTOS = 10
_JANELA_HISTORICO_DIAS = 30


@dataclass
class ThreatContext:
    """
    Contexto enriquecido de uma ameaça, enviado ao agente LLM para investigação.

    Atributos:
        evento_id:               Identificador único do evento atual.
        evento_atual:            Dicionário com os dados do evento bruto.
        score:                   ResultadoScore calculado pelo pipeline de ML.
        eventos_correlacionados: Eventos do mesmo source_ip nos últimos 10 minutos.
        historico_ip:            Aparições anteriores do source_ip nos últimos 30 dias.
        timestamp_inicio:        Início da janela de análise (ISO 8601 UTC).
        timestamp_fim:           Fim da janela de análise (ISO 8601 UTC).
    """

    evento_id: str
    evento_atual: dict
    score: object  # ResultadoScore — evita importação circular
    eventos_correlacionados: list[dict] = field(default_factory=list)
    historico_ip: list[dict] = field(default_factory=list)
    timestamp_inicio: str = ""
    timestamp_fim: str = ""


class ContextBuilder:
    """
    Busca e agrega contexto histórico no Elasticsearch para enriquecer alertas.

    Uso:
        builder = ContextBuilder(es_client)
        contexto = builder.construir(evento, score)
        # → ThreatContext com eventos correlacionados e histórico do IP
    """

    def __init__(self, es_client: object) -> None:
        """
        Inicializa o ContextBuilder com um cliente Elasticsearch.

        Args:
            es_client: Instância do cliente elasticsearch-py já configurado.
        """
        self._es = es_client

    def construir(self, evento: dict, score: object) -> ThreatContext:
        """
        Constrói o ThreatContext para um evento, buscando contexto no Elasticsearch.

        Busca eventos correlacionados do mesmo source_ip nos últimos 10 minutos
        e o histórico do source_ip nos últimos 30 dias. Em caso de qualquer
        falha do Elasticsearch, retorna ThreatContext com listas vazias sem
        lançar exceção.

        Args:
            evento: Dicionário do evento bruto (schema normalizado do ES).
            score:  ResultadoScore calculado pelo pipeline de ML.

        Returns:
            ThreatContext com contexto enriquecido ou listas vazias em caso de falha.
        """
        agora = datetime.now(timezone.utc)
        timestamp_fim = agora.isoformat()
        timestamp_inicio = (agora - timedelta(days=_JANELA_HISTORICO_DIAS)).isoformat()

        evento_id = evento.get("_id", "")
        source_ip = evento.get("source_ip", "")

        # Sem source_ip: retorna contexto vazio imediatamente
        if not source_ip:
            logger.debug(
                "Evento '%s' sem campo source_ip — retornando contexto vazio.",
                evento_id,
            )
            return ThreatContext(
                evento_id=evento_id,
                evento_atual=evento,
                score=score,
                eventos_correlacionados=[],
                historico_ip=[],
                timestamp_inicio=timestamp_inicio,
                timestamp_fim=timestamp_fim,
            )

        eventos_correlacionados = self._buscar_correlacionados(source_ip, agora)
        historico_ip = self._buscar_historico(source_ip, agora)

        return ThreatContext(
            evento_id=evento_id,
            evento_atual=evento,
            score=score,
            eventos_correlacionados=eventos_correlacionados,
            historico_ip=historico_ip,
            timestamp_inicio=timestamp_inicio,
            timestamp_fim=timestamp_fim,
        )

    # ----------------------------------------------------------
    # Métodos internos de busca
    # ----------------------------------------------------------

    def _buscar_correlacionados(self, source_ip: str, agora: datetime) -> list[dict]:
        """
        Busca eventos do mesmo source_ip nos últimos 10 minutos.

        Args:
            source_ip: Endereço IP de origem para correlação.
            agora:     Momento de referência para o cálculo da janela.

        Returns:
            Lista de dicionários com os eventos encontrados, ou [] em caso de falha.
        """
        inicio = (agora - timedelta(minutes=_JANELA_CORRELACAO_MINUTOS)).isoformat()
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"source_ip": source_ip}},
                        {"range": {"@timestamp": {"gte": inicio, "lte": agora.isoformat()}}},
                    ]
                }
            },
            "size": _SIZE_CORRELACIONADOS,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return self._executar_busca(query, descricao="correlacionados")

    def _buscar_historico(self, source_ip: str, agora: datetime) -> list[dict]:
        """
        Busca o histórico do source_ip nos últimos 30 dias.

        Args:
            source_ip: Endereço IP de origem para busca histórica.
            agora:     Momento de referência para o cálculo da janela.

        Returns:
            Lista de dicionários com os eventos encontrados, ou [] em caso de falha.
        """
        inicio = (agora - timedelta(days=_JANELA_HISTORICO_DIAS)).isoformat()
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"source_ip": source_ip}},
                        {"range": {"@timestamp": {"gte": inicio, "lte": agora.isoformat()}}},
                    ]
                }
            },
            "size": _SIZE_HISTORICO,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return self._executar_busca(query, descricao="histórico")

    def _executar_busca(self, query: dict, descricao: str) -> list[dict]:
        """
        Executa uma query no Elasticsearch com timeout de 2 segundos.

        Captura qualquer exceção e retorna lista vazia para garantir resiliência.

        Args:
            query:     Corpo da query DSL do Elasticsearch.
            descricao: Rótulo para logging (ex: "correlacionados", "histórico").

        Returns:
            Lista de dicionários extraídos de hits._source, ou [] em caso de falha.
        """
        try:
            resposta = self._es.search(
                body=query,
                request_timeout=_TIMEOUT_ES_SEGUNDOS,
            )
            hits = resposta.get("hits", {}).get("hits", [])
            eventos = [hit.get("_source", hit) for hit in hits]
            logger.debug(
                "Busca '%s' retornou %d evento(s).", descricao, len(eventos)
            )
            return eventos
        except Exception as exc:
            logger.warning(
                "Falha na busca '%s' no Elasticsearch: %s — retornando lista vazia.",
                descricao,
                exc,
            )
            return []
