"""
Classificador de Ameaças — AI-Powered Threat Hunter
====================================================
Responsabilidade:
    Recebe um evento de segurança e classifica qual tipo de ataque
    ele representa, com a probabilidade de cada classe.

Algoritmo: Random Forest (supervisionado)
    - Treinado com datasets públicos de ataques reais (CICIDS2017, NSL-KDD)
    - Ensemble de árvores de decisão — robusto a overfitting
    - Retorna probabilidades por classe, não apenas a classe vencedora

Classes de ameaça suportadas:
    - NORMAL              → Tráfego legítimo
    - BRUTE_FORCE         → Tentativas repetidas de autenticação
    - PORT_SCAN           → Varredura de portas (Nmap, etc.)
    - DDOS                → Ataque de negação de serviço distribuído
    - LATERAL_MOVEMENT    → Movimentação interna na rede
    - DATA_EXFILTRATION   → Vazamento de dados
    - PRIVILEGE_ESCALATION → Escalonamento de privilégios
"""

import numpy as np
import logging
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

logger = logging.getLogger("threat-hunter.ml.threat_classifier")

# Diretório para salvar o modelo treinado
ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


# =============================================================
# Mapeamento de classes de ameaça
# =============================================================

# Índice numérico → nome legível da ameaça
CLASSES_AMEACA = {
    0: "NORMAL",
    1: "BRUTE_FORCE",
    2: "PORT_SCAN",
    3: "DDOS",
    4: "LATERAL_MOVEMENT",
    5: "DATA_EXFILTRATION",
    6: "PRIVILEGE_ESCALATION",
}

# Severidade associada a cada classe (usada no score final)
SEVERIDADE_POR_CLASSE = {
    "NORMAL":               0,
    "BRUTE_FORCE":          70,
    "PORT_SCAN":            40,
    "DDOS":                 80,
    "LATERAL_MOVEMENT":     90,
    "DATA_EXFILTRATION":    95,
    "PRIVILEGE_ESCALATION": 85,
}


class ThreatClassifier:
    """
    Classifica eventos de segurança em tipos de ameaça conhecidos.

    Fluxo de uso:
        1. Treinar com dataset rotulado (CICIDS2017 ou similar)
        2. Para cada novo evento anômalo, chamar predict() ou predict_proba()
    """

    def __init__(self, n_estimators: int = 200, max_depth: int = 20):
        """
        Args:
            n_estimators: Número de árvores no ensemble.
                          Mais árvores = mais preciso, porém mais lento.
            max_depth:    Profundidade máxima de cada árvore.
                          Limitar evita overfitting.
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth

        self.modelo = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",  # Compensa desbalanceamento entre classes
            random_state=42,
            n_jobs=-1,
        )

        self.is_fitted = False

    # ----------------------------------------------------------
    # Treinamento
    # ----------------------------------------------------------

    def fit(self, X: np.ndarray, y: np.ndarray) -> "ThreatClassifier":
        """
        Treina o classificador com eventos rotulados.

        Args:
            X: Matriz de features (n_amostras, n_features).
            y: Array de labels (n_amostras,) com índices de CLASSES_AMEACA.

        Returns:
            Self (para encadeamento de chamadas).
        """
        logger.info(
            f"Treinando Random Forest com {X.shape[0]} amostras, "
            f"{len(np.unique(y))} classes..."
        )

        self.modelo.fit(X, y)
        self.is_fitted = True

        # Log das features mais importantes para interpretabilidade
        importancias = self.modelo.feature_importances_
        logger.info(
            f"Top 3 features mais importantes: "
            f"{np.argsort(importancias)[-3:][::-1].tolist()}"
        )

        logger.info("Random Forest treinado com sucesso.")
        return self

    def avaliar(self, X_test: np.ndarray, y_test: np.ndarray) -> str:
        """
        Avalia o modelo no conjunto de teste e retorna relatório de métricas.

        Args:
            X_test: Features do conjunto de teste.
            y_test: Labels reais do conjunto de teste.

        Returns:
            String com precision, recall e F1-score por classe.
        """
        self._verificar_treinamento()
        y_pred = self.modelo.predict(X_test)
        nomes_classes = [CLASSES_AMEACA[i] for i in sorted(CLASSES_AMEACA.keys())]
        return classification_report(y_test, y_pred, target_names=nomes_classes)

    # ----------------------------------------------------------
    # Predição
    # ----------------------------------------------------------

    def predict(self, X: np.ndarray) -> list[str]:
        """
        Retorna a classe de ameaça mais provável para cada evento.

        Args:
            X: Matriz de features (n_amostras, n_features).

        Returns:
            Lista de strings com o nome da ameaça detectada.
        """
        self._verificar_treinamento()
        indices = self.modelo.predict(X)
        return [CLASSES_AMEACA.get(i, "UNKNOWN") for i in indices]

    def predict_proba(self, X: np.ndarray) -> list[dict]:
        """
        Retorna a probabilidade de cada classe para cada evento.
        Útil para o agente LLM entender o grau de certeza da classificação.

        Args:
            X: Matriz de features (n_amostras, n_features).

        Returns:
            Lista de dicionários {nome_classe: probabilidade}.
        """
        self._verificar_treinamento()
        probabilidades = self.modelo.predict_proba(X)

        resultado = []
        for probs in probabilidades:
            resultado.append({
                CLASSES_AMEACA[i]: round(float(p), 4)
                for i, p in enumerate(probs)
            })
        return resultado

    def severidade_base(self, classe: str) -> int:
        """
        Retorna a severidade base (0-100) associada a uma classe de ameaça.

        Args:
            classe: Nome da classe (ex: "BRUTE_FORCE").

        Returns:
            Inteiro de 0 a 100.
        """
        return SEVERIDADE_POR_CLASSE.get(classe, 50)

    # ----------------------------------------------------------
    # Utilitários internos
    # ----------------------------------------------------------

    def _verificar_treinamento(self) -> None:
        """Lança exceção se o modelo ainda não foi treinado."""
        if not self.is_fitted:
            raise RuntimeError(
                "Modelo não treinado. Execute fit() antes de predict()."
            )

    # ----------------------------------------------------------
    # Persistência
    # ----------------------------------------------------------

    def salvar(self, caminho: Path = ARTIFACTS_DIR / "threat_classifier.joblib") -> None:
        """Salva o modelo treinado em disco."""
        joblib.dump(self, caminho)
        logger.info(f"Classificador de ameaças salvo em: {caminho}")

    @classmethod
    def carregar(cls, caminho: Path = ARTIFACTS_DIR / "threat_classifier.joblib") -> "ThreatClassifier":
        """Carrega um modelo previamente salvo."""
        classifier = joblib.load(caminho)
        logger.info(f"Classificador de ameaças carregado de: {caminho}")
        return classifier
