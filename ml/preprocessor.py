"""
Pré-processador de Eventos — AI-Powered Threat Hunter
======================================================
Responsabilidade:
    Transforma eventos brutos do Elasticsearch em vetores
    numéricos prontos para os modelos de Machine Learning.

    Cada evento de segurança precisa ser convertido em números
    porque os algoritmos de ML só entendem valores numéricos.

Exemplo de transformação:
    Entrada:  {"event_type": "auth_failure", "count": 847, "hour": 3}
    Saída:    [1.0, 0.0, 0.0, 847.0, 3.0, ...]  (vetor numérico)
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import logging
from pathlib import Path

logger = logging.getLogger("threat-hunter.ml.preprocessor")

# Diretório onde os artefatos de pré-processamento são salvos
ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


# =============================================================
# Features utilizadas pelos modelos
# Qualquer alteração aqui deve ser refletida no treinamento
# =============================================================

# Features numéricas — usadas diretamente após normalização
NUMERIC_FEATURES = [
    "count",           # Quantidade de eventos no intervalo
    "bytes_sent",      # Volume de dados enviados
    "bytes_received",  # Volume de dados recebidos
    "duration_ms",     # Duração da conexão em milissegundos
    "hour",            # Hora do evento (0-23)
    "day_of_week",     # Dia da semana (0=segunda, 6=domingo)
    "http_status",     # Código HTTP (quando aplicável)
]

# Features categóricas — serão convertidas em números
CATEGORICAL_FEATURES = [
    "event_type",  # Tipo do evento (auth_failure, network_connection, etc.)
    "protocol",    # Protocolo de rede (TCP, UDP, ICMP)
    "category",    # Categoria geral (authentication, network, application)
]

# Todos os tipos de evento conhecidos pelo sistema
KNOWN_EVENT_TYPES = [
    "auth_failure",
    "auth_success",
    "privilege_escalation",
    "session_closed",
    "network_connection",
    "network_alert",
    "http_request",
    "unknown",
]


class Preprocessor:
    """
    Transforma eventos de segurança em vetores numéricos.

    Fluxo:
        1. Extrai features relevantes do evento
        2. Preenche valores ausentes com defaults seguros
        3. Codifica categorias em números (LabelEncoder)
        4. Normaliza valores numéricos (StandardScaler)
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders: dict[str, LabelEncoder] = {}
        self.is_fitted = False

    # ----------------------------------------------------------
    # Extração de features
    # ----------------------------------------------------------

    def extrair_features(self, evento: dict) -> dict:
        """
        Extrai e padroniza as features de um evento bruto.
        Valores ausentes recebem defaults neutros (0 ou "unknown").

        Args:
            evento: Dicionário do evento vindo do Elasticsearch.

        Returns:
            Dicionário com apenas as features relevantes.
        """
        # Extrai hora e dia da semana do timestamp
        timestamp = pd.to_datetime(evento.get("timestamp"), utc=True, errors="coerce")
        hora = timestamp.hour if timestamp is not pd.NaT else 0
        dia_semana = timestamp.dayofweek if timestamp is not pd.NaT else 0

        return {
            # Numéricas
            "count":          float(evento.get("count", 1)),
            "bytes_sent":     float(evento.get("bytes_sent", 0)),
            "bytes_received": float(evento.get("bytes_received", 0)),
            "duration_ms":    float(evento.get("duration_ms", 0)),
            "hour":           float(hora),
            "day_of_week":    float(dia_semana),
            "http_status":    float(evento.get("http_status", 0)),
            # Categóricas
            "event_type":     evento.get("event_type", "unknown"),
            "protocol":       evento.get("protocol", "unknown"),
            "category":       evento.get("category", "unknown"),
        }

    # ----------------------------------------------------------
    # Treinamento do pré-processador
    # ----------------------------------------------------------

    def fit(self, eventos: list[dict]) -> "Preprocessor":
        """
        Aprende os parâmetros de normalização e codificação
        a partir de um conjunto de eventos de treinamento.

        Args:
            eventos: Lista de eventos brutos para treinamento.

        Returns:
            Self (para encadeamento de chamadas).
        """
        logger.info(f"Treinando pré-processador com {len(eventos)} eventos...")

        features_list = [self.extrair_features(e) for e in eventos]
        df = pd.DataFrame(features_list)

        # Treina um LabelEncoder para cada feature categórica
        for coluna in CATEGORICAL_FEATURES:
            encoder = LabelEncoder()
            encoder.fit(df[coluna].astype(str))
            self.label_encoders[coluna] = encoder
            logger.debug(f"LabelEncoder treinado para '{coluna}': {list(encoder.classes_)}")

        # Treina o scaler nas features numéricas
        df_numericas = self._codificar_categoricas(df)
        self.scaler.fit(df_numericas[NUMERIC_FEATURES + CATEGORICAL_FEATURES])

        self.is_fitted = True
        logger.info("Pré-processador treinado com sucesso.")
        return self

    # ----------------------------------------------------------
    # Transformação
    # ----------------------------------------------------------

    def transform(self, eventos: list[dict]) -> np.ndarray:
        """
        Transforma uma lista de eventos em matriz numérica normalizada.

        Args:
            eventos: Lista de eventos brutos.

        Returns:
            Array numpy com shape (n_eventos, n_features).

        Raises:
            RuntimeError: Se o pré-processador não foi treinado ainda.
        """
        if not self.is_fitted:
            raise RuntimeError(
                "Pré-processador não treinado. Execute fit() antes de transform()."
            )

        features_list = [self.extrair_features(e) for e in eventos]
        df = pd.DataFrame(features_list)
        df_codificado = self._codificar_categoricas(df)

        return self.scaler.transform(df_codificado[NUMERIC_FEATURES + CATEGORICAL_FEATURES])

    def fit_transform(self, eventos: list[dict]) -> np.ndarray:
        """Atalho para fit() seguido de transform()."""
        return self.fit(eventos).transform(eventos)

    # ----------------------------------------------------------
    # Métodos internos
    # ----------------------------------------------------------

    def _codificar_categoricas(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Converte colunas categóricas em valores numéricos.
        Valores desconhecidos (não vistos no treinamento) recebem -1.
        """
        df = df.copy()
        for coluna in CATEGORICAL_FEATURES:
            encoder = self.label_encoders.get(coluna)
            if encoder is None:
                df[coluna] = 0
                continue

            # Trata valores desconhecidos sem lançar exceção
            valores = df[coluna].astype(str)
            mascara_conhecidos = valores.isin(encoder.classes_)
            df[coluna] = np.where(
                mascara_conhecidos,
                encoder.transform(valores.where(mascara_conhecidos, encoder.classes_[0])),
                -1,  # Valor desconhecido
            )
        return df

    # ----------------------------------------------------------
    # Persistência
    # ----------------------------------------------------------

    def salvar(self, caminho: Path = ARTIFACTS_DIR / "preprocessor.joblib") -> None:
        """Salva o pré-processador treinado em disco."""
        joblib.dump(self, caminho)
        logger.info(f"Pré-processador salvo em: {caminho}")

    @classmethod
    def carregar(cls, caminho: Path = ARTIFACTS_DIR / "preprocessor.joblib") -> "Preprocessor":
        """Carrega um pré-processador previamente salvo."""
        preprocessor = joblib.load(caminho)
        logger.info(f"Pré-processador carregado de: {caminho}")
        return preprocessor
