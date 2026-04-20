"""
Detector de Anomalias — AI-Powered Threat Hunter
=================================================
Responsabilidade:
    Aprende o comportamento normal da rede durante um período
    de baseline (7-14 dias) e detecta qualquer desvio desse padrão.

Algoritmo: Isolation Forest (não supervisionado)
    - Não precisa de exemplos rotulados de ataques
    - Isola pontos anômalos construindo árvores de decisão aleatórias
    - Eventos raros (anômalos) são isolados com menos divisões
    - Retorna um score de anomalia entre -1 e 1

Por que Isolation Forest?
    - Eficiente em alta dimensionalidade
    - Funciona bem com dados desbalanceados (poucos ataques, muitos eventos normais)
    - Não assume distribuição específica dos dados
"""

import numpy as np
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
import joblib

logger = logging.getLogger("threat-hunter.ml.anomaly_detector")

# Diretório para salvar o modelo treinado
ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


class AnomalyDetector:
    """
    Detecta comportamentos anômalos usando Isolation Forest.

    Fluxo de uso:
        1. Coletar eventos normais por 7-14 dias (baseline)
        2. Chamar fit() com esses eventos
        3. Para cada novo evento, chamar predict() ou score()
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        """
        Args:
            contamination: Proporção esperada de anomalias nos dados (0.0 a 0.5).
                           0.05 = esperamos que 5% dos eventos sejam suspeitos.
            n_estimators:  Número de árvores no ensemble. Mais árvores = mais preciso,
                           porém mais lento.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators

        # Modelo principal
        self.modelo = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,       # Garante reprodutibilidade
            n_jobs=-1,             # Usa todos os núcleos disponíveis
        )

        self.is_fitted = False

    # ----------------------------------------------------------
    # Treinamento
    # ----------------------------------------------------------

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """
        Treina o modelo com dados de comportamento normal (baseline).

        Args:
            X: Matriz de features (n_amostras, n_features).
               Deve conter apenas eventos normais ou mistura com poucos ataques.

        Returns:
            Self (para encadeamento de chamadas).
        """
        logger.info(
            f"Treinando Isolation Forest com {X.shape[0]} amostras, "
            f"{X.shape[1]} features, contamination={self.contamination}..."
        )

        self.modelo.fit(X)
        self.is_fitted = True

        logger.info("Isolation Forest treinado com sucesso.")
        return self

    # ----------------------------------------------------------
    # Predição
    # ----------------------------------------------------------

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Classifica cada evento como normal ou anômalo.

        Args:
            X: Matriz de features (n_amostras, n_features).

        Returns:
            Array com valores:
                1  = normal
               -1  = anômalo (suspeito)
        """
        self._verificar_treinamento()
        return self.modelo.predict(X)

    def score_anomalia(self, X: np.ndarray) -> np.ndarray:
        """
        Retorna o score de anomalia para cada evento.

        O Isolation Forest retorna scores negativos — quanto mais negativo,
        mais anômalo. Invertemos e normalizamos para uma escala de 0 a 1,
        onde 1 = mais anômalo.

        Args:
            X: Matriz de features (n_amostras, n_features).

        Returns:
            Array de floats entre 0.0 e 1.0.
            Valores próximos de 1.0 indicam alta anomalia.
        """
        self._verificar_treinamento()

        # score_samples retorna valores negativos (mais negativo = mais anômalo)
        scores_brutos = self.modelo.score_samples(X)

        # Inverte o sinal: mais anômalo → valor mais alto
        scores_invertidos = -scores_brutos

        # Normaliza para [0, 1] usando min-max
        minimo = scores_invertidos.min()
        maximo = scores_invertidos.max()

        if maximo == minimo:
            # Todos os eventos têm o mesmo score — retorna 0 para todos
            return np.zeros(len(scores_invertidos))

        return (scores_invertidos - minimo) / (maximo - minimo)

    def is_anomalo(self, X: np.ndarray, threshold: float = 0.7) -> np.ndarray:
        """
        Retorna booleano indicando se cada evento é anômalo.

        Args:
            X:         Matriz de features.
            threshold: Score mínimo para considerar anômalo (0.0 a 1.0).

        Returns:
            Array de booleanos.
        """
        return self.score_anomalia(X) >= threshold

    # ----------------------------------------------------------
    # Utilitários internos
    # ----------------------------------------------------------

    def _verificar_treinamento(self) -> None:
        """Lança exceção se o modelo ainda não foi treinado."""
        if not self.is_fitted:
            raise RuntimeError(
                "Modelo não treinado. Execute fit() antes de predict() ou score_anomalia()."
            )

    # ----------------------------------------------------------
    # Persistência
    # ----------------------------------------------------------

    def salvar(self, caminho: Path = ARTIFACTS_DIR / "anomaly_detector.joblib") -> None:
        """Salva o modelo treinado em disco."""
        joblib.dump(self, caminho)
        logger.info(f"Detector de anomalias salvo em: {caminho}")

    @classmethod
    def carregar(cls, caminho: Path = ARTIFACTS_DIR / "anomaly_detector.joblib") -> "AnomalyDetector":
        """Carrega um modelo previamente salvo."""
        detector = joblib.load(caminho)
        logger.info(f"Detector de anomalias carregado de: {caminho}")
        return detector
