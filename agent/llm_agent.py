"""
LLMAgent — AI-Powered Threat Hunter
=====================================
Responsabilidade:
    Orquestrar a investigação de incidentes de segurança usando a API
    Anthropic (Claude). Recebe um ThreatContext, monta o prompt com os
    dados sanitizados, chama a API com retry e backoff exponencial, e
    retorna um IncidentReport estruturado.

    Nunca lança exceção — em caso de falha total, retorna IncidentReport
    com confianca=0.0 e mensagem de erro no resumo.

Requisitos: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 14.1, 14.4
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

import anthropic

from agent.context_builder import ThreatContext
from agent.mitre_mapper import MITREMapper
from agent.report_generator import IncidentReport, ReportGenerator, _proximo_incident_id, _timestamp_utc_agora

if TYPE_CHECKING:
    pass

logger = logging.getLogger("threat-hunter.agent.llm_agent")

# Configurações de retry e timeout
_MAX_TENTATIVAS = 3
_TIMEOUT_SEGUNDOS = 30
_BACKOFF_BASE = 1  # segundos (1s, 2s, 4s)

# Diretório dos prompts
_DIR_PROMPTS = Path(__file__).parent / "prompts"

# Padrão de caracteres permitidos em campos de usuário (sanitização)
_PATTERN_SANITIZACAO = re.compile(r"[^\w\s\.\-\:\/@\[\]\{\},\"']+", re.UNICODE)


def _carregar_prompt(nome_arquivo: str) -> str:
    """
    Carrega o conteúdo de um arquivo de prompt.

    Args:
        nome_arquivo: Nome do arquivo dentro de agent/prompts/.

    Returns:
        Conteúdo do arquivo como string.

    Raises:
        FileNotFoundError: Se o arquivo não existir.
    """
    caminho = _DIR_PROMPTS / nome_arquivo
    return caminho.read_text(encoding="utf-8")


def _sanitizar(valor: object) -> str:
    """
    Sanitiza um valor para inclusão segura em prompts LLM.

    Remove caracteres que poderiam ser usados para injeção de prompt,
    preservando caracteres alfanuméricos, espaços e pontuação comum.

    Args:
        valor: Valor a sanitizar (será convertido para string).

    Returns:
        String sanitizada.
    """
    texto = str(valor)
    # Limita o tamanho para evitar prompts excessivamente longos
    texto = texto[:2000]
    return _PATTERN_SANITIZACAO.sub("", texto)


def _ordenar_linha_do_tempo(linha_do_tempo: list[dict]) -> list[dict]:
    """
    Ordena a linha do tempo por timestamp crescente.

    Eventos sem timestamp válido são mantidos no final.

    Args:
        linha_do_tempo: Lista de dicionários com campo 'timestamp'.

    Returns:
        Lista ordenada por timestamp crescente.
    """
    def chave_ordenacao(evento: dict) -> str:
        ts = evento.get("timestamp", "")
        return ts if isinstance(ts, str) else ""

    return sorted(linha_do_tempo, key=chave_ordenacao)


def _substituir_placeholder(template: str, chave: str, valor: str) -> str:
    """
    Substitui um placeholder {chave} no template pelo valor fornecido.

    Usa substituição simples de string para evitar conflitos com chaves
    literais `{` e `}` presentes no template (ex: blocos JSON de exemplo).

    Args:
        template: String do template com placeholders no formato {chave}.
        chave:    Nome do placeholder a substituir.
        valor:    Valor a inserir no lugar do placeholder.

    Returns:
        Template com o placeholder substituído.
    """
    return template.replace("{" + chave + "}", valor)


def _montar_prompt_investigacao(contexto: ThreatContext, prompt_template: str) -> str:
    """
    Monta o prompt de investigação com os dados do ThreatContext sanitizados.

    Args:
        contexto:         ThreatContext com os dados do evento.
        prompt_template:  Template do prompt de investigação.

    Returns:
        Prompt formatado e pronto para envio ao LLM.
    """
    score = contexto.score
    score_valor = str(getattr(score, "score", 0.0))
    severidade = getattr(score, "severidade", "DESCONHECIDO")
    classe_ameaca = getattr(score, "classe_ameaca", "DESCONHECIDO")
    score_anomalia = str(getattr(score, "score_anomalia", 0.0))

    evento = contexto.evento_atual
    source_ip = _sanitizar(evento.get("source_ip", "N/A"))
    event_type = _sanitizar(evento.get("event_type", "N/A"))
    timestamp = _sanitizar(evento.get("@timestamp", evento.get("timestamp", "N/A")))

    # Sanitiza listas de eventos para evitar injeção de prompt
    correlacionados_str = _sanitizar(str(contexto.eventos_correlacionados[:10]))
    historico_str = _sanitizar(str(contexto.historico_ip[:10]))
    evento_str = _sanitizar(str(evento))

    substituicoes = {
        "evento_id": _sanitizar(contexto.evento_id),
        "event_type": event_type,
        "source_ip": source_ip,
        "score": score_valor,
        "severidade": severidade,
        "classe_ameaca": classe_ameaca,
        "score_anomalia": score_anomalia,
        "timestamp": timestamp,
        "evento_atual": evento_str,
        "eventos_correlacionados": correlacionados_str,
        "historico_ip": historico_str,
        "timestamp_inicio": _sanitizar(contexto.timestamp_inicio),
        "timestamp_fim": _sanitizar(contexto.timestamp_fim),
    }

    resultado = prompt_template
    for chave, valor in substituicoes.items():
        resultado = _substituir_placeholder(resultado, chave, valor)
    return resultado


def _montar_prompt_relatorio(
    analise: str,
    contexto: ThreatContext,
    tecnicas_mitre: list[str],
    incident_id: str,
    timestamp_geracao: str,
    prompt_template: str,
) -> str:
    """
    Monta o prompt de geração de relatório.

    Args:
        analise:           Texto da análise de investigação do LLM.
        contexto:          ThreatContext com os dados do evento.
        tecnicas_mitre:    Lista de técnicas ATT&CK identificadas.
        incident_id:       ID do incidente a ser gerado.
        timestamp_geracao: Timestamp de geração do relatório.
        prompt_template:   Template do prompt de relatório.

    Returns:
        Prompt formatado e pronto para envio ao LLM.
    """
    score = contexto.score
    score_valor = str(getattr(score, "score", 0.0))
    severidade = getattr(score, "severidade", "DESCONHECIDO")
    classe_ameaca = getattr(score, "classe_ameaca", "DESCONHECIDO")

    substituicoes = {
        "analise_investigacao": _sanitizar(analise),
        "score": score_valor,
        "severidade": severidade,
        "classe_ameaca": classe_ameaca,
        "tecnicas_mitre": str(tecnicas_mitre),
        "timestamp_geracao": timestamp_geracao,
        "incident_id": incident_id,
    }

    resultado = prompt_template
    for chave, valor in substituicoes.items():
        resultado = _substituir_placeholder(resultado, chave, valor)
    return resultado


class LLMAgent:
    """
    Orquestra a investigação de incidentes via API Anthropic (Claude).

    Uso:
        agent = LLMAgent(api_key="sk-...")
        report = agent.investigar(contexto)
        # → IncidentReport com análise completa ou confianca=0.0 em caso de falha
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "claude-3-5-sonnet-20241022",
    ) -> None:
        """
        Inicializa o LLMAgent com a chave de API e o modelo a usar.

        A api_key é lida exclusivamente de variável de ambiente
        ANTHROPIC_API_KEY se não fornecida diretamente.

        Args:
            api_key: Chave de API Anthropic. Se vazia, usa ANTHROPIC_API_KEY.
            model:   Identificador do modelo Claude a usar.
        """
        chave = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._model = model
        self._client = anthropic.Anthropic(api_key=chave)
        self._mitre_mapper = MITREMapper()
        self._report_generator = ReportGenerator()

        logger.debug("LLMAgent inicializado com modelo '%s'.", model)

    def investigar(self, contexto: ThreatContext) -> IncidentReport:
        """
        Investiga um incidente de segurança e retorna um relatório estruturado.

        Carrega os prompts de investigação e relatório, monta o prompt com
        os dados do ThreatContext sanitizados, chama a API Anthropic com
        timeout de 30s e retry com backoff exponencial (3 tentativas).

        Em caso de falha total, retorna IncidentReport com confianca=0.0
        sem lançar exceção.

        A linha_do_tempo do relatório é ordenada por timestamp crescente.

        Args:
            contexto: ThreatContext com evento atual, correlacionados e histórico.

        Returns:
            IncidentReport com análise completa ou com confianca=0.0 em falha.
        """
        incident_id = _proximo_incident_id()
        timestamp_geracao = _timestamp_utc_agora()

        try:
            prompt_investigacao = _carregar_prompt("investigation.txt")
            prompt_relatorio = _carregar_prompt("report.txt")
        except FileNotFoundError as exc:
            logger.error("Arquivo de prompt não encontrado: %s", exc)
            return self._relatorio_erro(
                incident_id,
                timestamp_geracao,
                f"Arquivo de prompt não encontrado: {exc}",
            )

        # Mapeia técnicas MITRE para o contexto
        classe_ameaca = getattr(contexto.score, "classe_ameaca", "")
        tecnicas_mitre = self._mitre_mapper.mapear(classe_ameaca, contexto)

        # Fase 1: Investigação
        analise = self._chamar_api_com_retry(
            prompt=_montar_prompt_investigacao(contexto, prompt_investigacao),
            incident_id=incident_id,
        )
        if analise is None:
            return self._relatorio_erro(
                incident_id,
                timestamp_geracao,
                "Análise automática indisponível — revisão manual necessária.",
            )

        # Fase 2: Geração do relatório estruturado
        prompt_rel = _montar_prompt_relatorio(
            analise=analise,
            contexto=contexto,
            tecnicas_mitre=tecnicas_mitre,
            incident_id=incident_id,
            timestamp_geracao=timestamp_geracao,
            prompt_template=prompt_relatorio,
        )
        resposta_relatorio = self._chamar_api_com_retry(
            prompt=prompt_rel,
            incident_id=incident_id,
        )
        if resposta_relatorio is None:
            return self._relatorio_erro(
                incident_id,
                timestamp_geracao,
                "Geração de relatório indisponível — revisão manual necessária.",
            )

        # Parseia e valida o relatório
        report = self._report_generator.gerar(contexto, resposta_relatorio)

        # Garante incident_id consistente (o gerador cria um novo; substituímos)
        report = IncidentReport(
            incident_id=incident_id,
            severidade=report.severidade,
            resumo=report.resumo,
            linha_do_tempo=_ordenar_linha_do_tempo(report.linha_do_tempo),
            impacto_estimado=report.impacto_estimado,
            acoes_recomendadas=report.acoes_recomendadas,
            tecnicas_mitre=report.tecnicas_mitre or tecnicas_mitre,
            confianca=report.confianca,
            timestamp_geracao=report.timestamp_geracao,
            raw_llm_response=resposta_relatorio,
        )

        logger.info(
            "Incidente '%s' investigado com confiança %.2f (severidade: %s).",
            incident_id,
            report.confianca,
            report.severidade,
        )
        return report

    # ----------------------------------------------------------
    # Métodos internos
    # ----------------------------------------------------------

    def _chamar_api_com_retry(
        self,
        prompt: str,
        incident_id: str,
    ) -> str | None:
        """
        Chama a API Anthropic com retry e backoff exponencial.

        Realiza até 3 tentativas com esperas de 1s, 2s e 4s entre elas.
        Timeout de 30s por tentativa.

        Args:
            prompt:      Texto do prompt a enviar.
            incident_id: ID do incidente (para logging).

        Returns:
            Texto da resposta do LLM, ou None se todas as tentativas falharem.
        """
        for tentativa in range(_MAX_TENTATIVAS):
            try:
                resposta = self._client.messages.create(
                    model=self._model,
                    max_tokens=4096,
                    timeout=_TIMEOUT_SEGUNDOS,
                    messages=[{"role": "user", "content": prompt}],
                )
                texto = resposta.content[0].text
                logger.debug(
                    "API respondeu na tentativa %d para incidente '%s'.",
                    tentativa + 1,
                    incident_id,
                )
                return texto

            except Exception as exc:
                espera = _BACKOFF_BASE * (2 ** tentativa)
                logger.warning(
                    "Tentativa %d/%d falhou para incidente '%s': %s. "
                    "Aguardando %ds antes de tentar novamente.",
                    tentativa + 1,
                    _MAX_TENTATIVAS,
                    incident_id,
                    exc,
                    espera,
                )
                if tentativa < _MAX_TENTATIVAS - 1:
                    time.sleep(espera)

        logger.error(
            "Todas as %d tentativas falharam para incidente '%s'.",
            _MAX_TENTATIVAS,
            incident_id,
        )
        return None

    @staticmethod
    def _relatorio_erro(
        incident_id: str,
        timestamp_geracao: str,
        mensagem_erro: str,
    ) -> IncidentReport:
        """
        Cria um IncidentReport de erro com confianca=0.0.

        Args:
            incident_id:       ID do incidente.
            timestamp_geracao: Timestamp de geração.
            mensagem_erro:     Mensagem descritiva do erro.

        Returns:
            IncidentReport com confianca=0.0 e mensagem de erro no resumo.
        """
        return IncidentReport(
            incident_id=incident_id,
            severidade="DESCONHECIDO",
            resumo=mensagem_erro,
            linha_do_tempo=[],
            impacto_estimado="Não foi possível determinar o impacto — revisão manual necessária.",
            acoes_recomendadas=["Revisar manualmente o evento de segurança"],
            tecnicas_mitre=[],
            confianca=0.0,
            timestamp_geracao=timestamp_geracao,
            raw_llm_response="",
        )
