"""
ReportGenerator — AI-Powered Threat Hunter
==========================================
Responsabilidade:
    Parsear a resposta JSON do LLM e produzir um IncidentReport estruturado,
    garantindo que todos os campos obrigatórios estejam presentes e válidos.

    Para incidentes críticos (score >= 80), garante que acoes_recomendadas
    inclui pelo menos uma ação de bloqueio de firewall.

Requisitos: 6.1, 6.2, 6.3, 6.4, 6.5
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("threat-hunter.agent.report_generator")

# Threshold para exigir ação de firewall nas recomendações
_THRESHOLD_CRITICO = 80

# Contador sequencial de incidentes por ano (em memória)
_contadores_por_ano: dict[int, int] = {}

# Palavras-chave que identificam uma ação de bloqueio de firewall
_PALAVRAS_FIREWALL = ("firewall", "bloquear", "block", "iptables", "nftables", "drop")

# Ação de fallback para bloqueio de firewall
_ACAO_FIREWALL_FALLBACK = "Bloquear IP de origem no firewall imediatamente"


@dataclass
class IncidentReport:
    """
    Relatório estruturado de um incidente de segurança investigado pelo LLM.

    Atributos:
        incident_id:          Identificador único no formato INC-YYYY-NNNN.
        severidade:           Nível de severidade (CRITICO, ALTO, MEDIO, BAIXO, INFO).
        resumo:               Descrição do incidente em 1-2 frases.
        linha_do_tempo:       Lista de eventos ordenados por timestamp crescente.
        impacto_estimado:     Descrição do impacto potencial nos sistemas.
        acoes_recomendadas:   Lista de ações acionáveis (não-vazia).
        tecnicas_mitre:       Lista de técnicas ATT&CK identificadas.
        confianca:            Nível de confiança da análise (0.0–1.0).
        timestamp_geracao:    Timestamp de geração do relatório (ISO 8601 UTC).
        raw_llm_response:     Resposta bruta retornada pelo LLM.
    """

    incident_id: str
    severidade: str
    resumo: str
    linha_do_tempo: list[dict]
    impacto_estimado: str
    acoes_recomendadas: list[str]
    tecnicas_mitre: list[str]
    confianca: float
    timestamp_geracao: str
    raw_llm_response: str


def _proximo_incident_id() -> str:
    """
    Gera o próximo incident_id sequencial no formato INC-YYYY-NNNN.

    O contador é mantido em memória por ano. Reinicia a cada novo ano.

    Returns:
        String no formato INC-YYYY-NNNN (ex: INC-2025-0001).
    """
    ano = datetime.now(timezone.utc).year
    _contadores_por_ano[ano] = _contadores_por_ano.get(ano, 0) + 1
    return f"INC-{ano}-{_contadores_por_ano[ano]:04d}"


def _timestamp_utc_agora() -> str:
    """Retorna o timestamp atual em formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


def _tem_acao_firewall(acoes: list[str]) -> bool:
    """
    Verifica se a lista de ações contém pelo menos uma ação de bloqueio de firewall.

    Args:
        acoes: Lista de strings com ações recomendadas.

    Returns:
        True se alguma ação menciona firewall/bloqueio, False caso contrário.
    """
    for acao in acoes:
        if any(palavra in acao.lower() for palavra in _PALAVRAS_FIREWALL):
            return True
    return False


def _extrair_json_da_resposta(resposta_llm: str) -> dict:
    """
    Extrai o objeto JSON da resposta do LLM, tolerando markdown code blocks.

    Args:
        resposta_llm: String com a resposta bruta do LLM.

    Returns:
        Dicionário parseado do JSON.

    Raises:
        json.JSONDecodeError: Se não for possível parsear o JSON.
    """
    texto = resposta_llm.strip()

    # Remove blocos de código markdown (```json ... ``` ou ``` ... ```)
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", texto)
    if match:
        texto = match.group(1).strip()

    return json.loads(texto)


class ReportGenerator:
    """
    Parseia a resposta JSON do LLM e produz um IncidentReport estruturado.

    Garante que todos os campos obrigatórios estejam presentes e válidos,
    aplicando fallbacks quando necessário.

    Uso:
        generator = ReportGenerator()
        report = generator.gerar(contexto, resposta_llm)
    """

    def gerar(self, contexto: object, resposta_llm: str) -> IncidentReport:
        """
        Parseia a resposta do LLM e retorna um IncidentReport válido.

        Em caso de JSON inválido, retorna um IncidentReport com confianca=0.0
        e mensagem de erro no resumo, sem lançar exceção.

        Para score >= 80, garante que acoes_recomendadas inclui pelo menos
        uma ação de bloqueio de firewall.

        Args:
            contexto:     ThreatContext com os dados do evento e score.
            resposta_llm: String JSON retornada pelo LLM.

        Returns:
            IncidentReport estruturado e validado.
        """
        incident_id = _proximo_incident_id()
        timestamp_geracao = _timestamp_utc_agora()

        try:
            dados = _extrair_json_da_resposta(resposta_llm)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "Falha ao parsear JSON do LLM para incidente '%s': %s",
                incident_id,
                exc,
            )
            return IncidentReport(
                incident_id=incident_id,
                severidade="DESCONHECIDO",
                resumo=f"Erro ao parsear resposta do LLM: {exc}",
                linha_do_tempo=[],
                impacto_estimado="Não foi possível determinar o impacto — revisão manual necessária.",
                acoes_recomendadas=["Revisar manualmente o evento de segurança"],
                tecnicas_mitre=[],
                confianca=0.0,
                timestamp_geracao=timestamp_geracao,
                raw_llm_response=resposta_llm,
            )

        # Extrai score do contexto para verificar threshold crítico
        score = self._extrair_score(contexto)

        # Garante campos obrigatórios com fallbacks
        acoes = dados.get("acoes_recomendadas") or []
        if not isinstance(acoes, list) or not acoes:
            acoes = ["Revisar manualmente o evento de segurança"]

        impacto = dados.get("impacto_estimado") or ""
        if not isinstance(impacto, str) or not impacto.strip():
            impacto = "Impacto não determinado — revisão manual necessária."

        # Para score >= 80, garante ação de bloqueio de firewall
        if score >= _THRESHOLD_CRITICO and not _tem_acao_firewall(acoes):
            acoes = [_ACAO_FIREWALL_FALLBACK] + acoes
            logger.debug(
                "Ação de firewall adicionada automaticamente para incidente crítico '%s' (score=%.1f).",
                incident_id,
                score,
            )

        # Valida e normaliza timestamp_geracao
        ts_geracao = dados.get("timestamp_geracao") or ""
        if not self._timestamp_valido(ts_geracao):
            ts_geracao = timestamp_geracao

        # Valida confiança
        confianca = dados.get("confianca", 0.0)
        try:
            confianca = float(confianca)
            confianca = max(0.0, min(1.0, confianca))
        except (TypeError, ValueError):
            confianca = 0.0

        return IncidentReport(
            incident_id=incident_id,
            severidade=dados.get("severidade") or "DESCONHECIDO",
            resumo=dados.get("resumo") or "Resumo não disponível.",
            linha_do_tempo=dados.get("linha_do_tempo") or [],
            impacto_estimado=impacto,
            acoes_recomendadas=acoes,
            tecnicas_mitre=dados.get("tecnicas_mitre") or [],
            confianca=confianca,
            timestamp_geracao=ts_geracao,
            raw_llm_response=resposta_llm,
        )

    # ----------------------------------------------------------
    # Métodos internos
    # ----------------------------------------------------------

    @staticmethod
    def _extrair_score(contexto: object) -> float:
        """
        Extrai o score numérico do ThreatContext de forma segura.

        Args:
            contexto: ThreatContext (ou qualquer objeto com atributo score).

        Returns:
            Score como float, ou 0.0 se não disponível.
        """
        try:
            score_obj = getattr(contexto, "score", None)
            if score_obj is None:
                return 0.0
            # ResultadoScore tem atributo .score
            if hasattr(score_obj, "score"):
                return float(score_obj.score)
            return float(score_obj)
        except (TypeError, ValueError, AttributeError):
            return 0.0

    @staticmethod
    def _timestamp_valido(ts: str) -> bool:
        """
        Verifica se uma string é um timestamp ISO 8601 UTC válido.

        Args:
            ts: String a verificar.

        Returns:
            True se válido, False caso contrário.
        """
        if not ts or not isinstance(ts, str):
            return False
        try:
            # Aceita formatos com e sem microsegundos, com Z ou +00:00
            ts_normalizado = ts.replace("Z", "+00:00")
            datetime.fromisoformat(ts_normalizado)
            return True
        except ValueError:
            return False
