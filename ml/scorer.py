"""
Calculador de Score de Risco — AI-Powered Threat Hunter
========================================================
Responsabilidade:
    Combina os resultados do Detector de Anomalias e do Classificador
    de Ameaças para gerar um score de risco único de 0 a 100.

    Score 0   = comportamento completamente normal
    Score 100 = ameaça crítica com alta certeza

Fórmula:
    score_final = (score_anomalia * peso_anomalia) +
                  (severidade_classe * peso_classificacao)

    Os pesos são ajustáveis conforme a confiança de cada modelo.
"""

import numpy as np
import logging
from dataclasses import dataclass, field

from ml.anomaly_detection.detector import AnomalyDetector
from ml.threat_classifier.classifier import ThreatClassifier, SEVERIDADE_POR_CLASSE

logger = logging.getLogger("threat-hunter.ml.scorer")


# =============================================================
# Thresholds de severidade para roteamento de alertas
# =============================================================

THRESHOLD_CRITICO  = 80  # Aciona resposta automática imediata
THRESHOLD_ALTO     = 60  # Aciona agente LLM para investigação
THRESHOLD_MEDIO    = 40  # Registra alerta para revisão humana
THRESHOLD_BAIXO    = 20  # Log informativo apenas


@dataclass
class ResultadoScore:
    """
    Resultado completo da análise de risco de um evento.

    Agrupa todas as informações geradas pelos dois modelos
    em um único objeto para facilitar o consumo pelo agente LLM.
    """
    # Score final combinado (0-100)
    score: float

    # Nível de severidade textual
    severidade: str

    # Resultado do detector de anomalias
    score_anomalia: float          # 0.0 a 1.0
    is_anomalo: bool

    # Resultado do classificador
    classe_ameaca: str             # Ex: "BRUTE_FORCE"
    probabilidades: dict           # {classe: probabilidade}

    # Metadados para rastreabilidade
    evento_id: str = ""
    requer_resposta_automatica: bool = False
    requer_investigacao_llm: bool = False


class RiskScorer:
    """
    Orquestra os dois modelos de ML e produz um score de risco unificado.

    Uso:
        scorer = RiskScorer(detector, classifier)
        resultado = scorer.calcular(evento_normalizado, vetor_features)
    """

    # Pesos na composição do score final
    # Anomalia tem peso menor pois gera mais falsos positivos
    PESO_ANOMALIA       = 0.35
    PESO_CLASSIFICACAO  = 0.65

    def __init__(self, detector: AnomalyDetector, classifier: ThreatClassifier):
        """
        Args:
            detector:   Modelo de detecção de anomalias (já treinado).
            classifier: Modelo de classificação de ameaças (já treinado).
        """
        self.detector   = detector
        self.classifier = classifier

    # ----------------------------------------------------------
    # Cálculo do score
    # ----------------------------------------------------------

    def calcular(self, evento: dict, X: np.ndarray) -> ResultadoScore:
        """
        Calcula o score de risco completo para um único evento.

        Args:
            evento: Dicionário do evento bruto (para metadados).
            X:      Vetor de features pré-processado (shape: 1, n_features).

        Returns:
            ResultadoScore com todas as informações da análise.
        """
        # --- Modelo 1: Detecção de anomalia ---
        score_anomalia = float(self.detector.score_anomalia(X)[0])
        is_anomalo     = bool(self.detector.is_anomalo(X)[0])

        # --- Modelo 2: Classificação da ameaça ---
        classe_ameaca  = self.classifier.predict(X)[0]
        probabilidades = self.classifier.predict_proba(X)[0]

        # --- Composição do score final ---
        severidade_base  = self.classifier.severidade_base(classe_ameaca)
        score_final      = self._compor_score(score_anomalia, severidade_base)

        # --- Determinação do nível de severidade ---
        nivel_severidade = self._classificar_severidade(score_final)

        resultado = ResultadoScore(
            score                    = round(score_final, 2),
            severidade               = nivel_severidade,
            score_anomalia           = round(score_anomalia, 4),
            is_anomalo               = is_anomalo,
            classe_ameaca            = classe_ameaca,
            probabilidades           = probabilidades,
            evento_id                = evento.get("_id", ""),
            requer_resposta_automatica = score_final >= THRESHOLD_CRITICO,
            requer_investigacao_llm    = score_final >= THRESHOLD_ALTO,
        )

        logger.info(
            f"Score calculado: {resultado.score} | "
            f"Severidade: {resultado.severidade} | "
            f"Classe: {resultado.classe_ameaca} | "
            f"Anomalia: {resultado.score_anomalia:.3f}"
        )

        return resultado

    def calcular_lote(self, eventos: list[dict], X: np.ndarray) -> list[ResultadoScore]:
        """
        Calcula scores para múltiplos eventos de uma vez.
        Mais eficiente que chamar calcular() em loop.

        Args:
            eventos: Lista de eventos brutos.
            X:       Matriz de features (n_eventos, n_features).

        Returns:
            Lista de ResultadoScore na mesma ordem dos eventos.
        """
        scores_anomalia  = self.detector.score_anomalia(X)
        is_anomalos      = self.detector.is_anomalo(X)
        classes          = self.classifier.predict(X)
        probabilidades   = self.classifier.predict_proba(X)

        resultados = []
        for i, evento in enumerate(eventos):
            severidade_base  = self.classifier.severidade_base(classes[i])
            score_final      = self._compor_score(float(scores_anomalia[i]), severidade_base)
            nivel_severidade = self._classificar_severidade(score_final)

            resultados.append(ResultadoScore(
                score                      = round(score_final, 2),
                severidade                 = nivel_severidade,
                score_anomalia             = round(float(scores_anomalia[i]), 4),
                is_anomalo                 = bool(is_anomalos[i]),
                classe_ameaca              = classes[i],
                probabilidades             = probabilidades[i],
                evento_id                  = evento.get("_id", ""),
                requer_resposta_automatica = score_final >= THRESHOLD_CRITICO,
                requer_investigacao_llm    = score_final >= THRESHOLD_ALTO,
            ))

        return resultados

    # ----------------------------------------------------------
    # Métodos internos
    # ----------------------------------------------------------

    def _compor_score(self, score_anomalia: float, severidade_base: int) -> float:
        """
        Combina score de anomalia (0-1) e severidade base (0-100)
        em um score final de 0 a 100.
        """
        componente_anomalia      = score_anomalia * 100 * self.PESO_ANOMALIA
        componente_classificacao = severidade_base * self.PESO_CLASSIFICACAO
        return min(componente_anomalia + componente_classificacao, 100.0)

    @staticmethod
    def _classificar_severidade(score: float) -> str:
        """Converte score numérico em nível textual de severidade."""
        if score >= THRESHOLD_CRITICO:
            return "CRITICO"
        if score >= THRESHOLD_ALTO:
            return "ALTO"
        if score >= THRESHOLD_MEDIO:
            return "MEDIO"
        if score >= THRESHOLD_BAIXO:
            return "BAIXO"
        return "INFO"
