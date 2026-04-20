"""
Script de Treinamento dos Modelos — AI-Powered Threat Hunter
=============================================================
Responsabilidade:
    Orquestra o treinamento completo do pipeline de ML:
        1. Carrega dados do Elasticsearch (eventos reais coletados)
        2. Pré-processa e normaliza as features
        3. Treina o Detector de Anomalias (não supervisionado)
        4. Treina o Classificador de Ameaças (supervisionado)
        5. Avalia os modelos e exibe métricas
        6. Salva todos os artefatos em disco

Uso:
    python -m ml.trainer

    Variáveis de ambiente necessárias (.env):
        ELASTIC_HOST, ELASTIC_PORT, ELASTIC_USERNAME, ELASTIC_PASSWORD

Datasets recomendados para treinamento supervisionado:
    - CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
    - NSL-KDD:    https://www.unb.ca/cic/datasets/nsl.html
    Coloque os CSVs em ml/datasets/ antes de executar.
"""

import os
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from ml.preprocessor import Preprocessor
from ml.anomaly_detection.detector import AnomalyDetector
from ml.threat_classifier.classifier import ThreatClassifier, CLASSES_AMEACA

# Carrega variáveis do .env
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("threat-hunter.ml.trainer")

# Caminhos
DATASETS_DIR  = Path(__file__).parent / "datasets"
ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


# =============================================================
# Funções de carregamento de dados
# =============================================================

def carregar_eventos_elasticsearch(limite: int = 50_000) -> list[dict]:
    """
    Busca eventos coletados do Elasticsearch para treinamento
    do modelo de anomalias (não supervisionado).

    Args:
        limite: Número máximo de eventos a carregar.

    Returns:
        Lista de dicionários com os eventos.
    """
    logger.info(f"Conectando ao Elasticsearch para carregar até {limite} eventos...")

    es = Elasticsearch(
        f"http://{os.getenv('ELASTIC_HOST', 'localhost')}:{os.getenv('ELASTIC_PORT', 9200)}",
        basic_auth=(
            os.getenv("ELASTIC_USERNAME", "elastic"),
            os.getenv("ELASTIC_PASSWORD", "changeme123"),
        ),
    )

    resposta = es.search(
        index="threat-events-*",
        body={
            "size": limite,
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    eventos = [hit["_source"] for hit in resposta["hits"]["hits"]]
    logger.info(f"{len(eventos)} eventos carregados do Elasticsearch.")
    return eventos


def carregar_dataset_cicids(caminho: Path) -> tuple[pd.DataFrame, pd.Series]:
    """
    Carrega e prepara o dataset CICIDS2017 para treinamento supervisionado.

    O CICIDS2017 contém tráfego de rede rotulado com tipos de ataque reais.
    Download: https://www.unb.ca/cic/datasets/ids-2017.html

    Args:
        caminho: Caminho para o arquivo CSV do CICIDS2017.

    Returns:
        Tupla (features_df, labels_series).
    """
    logger.info(f"Carregando dataset CICIDS2017 de: {caminho}")

    df = pd.read_csv(caminho, low_memory=False)

    # Remove espaços dos nomes das colunas (problema comum no CICIDS2017)
    df.columns = df.columns.str.strip()

    # Mapeamento de labels do CICIDS2017 para as classes do projeto
    mapa_labels = {
        "BENIGN":                    0,  # NORMAL
        "FTP-Patator":               1,  # BRUTE_FORCE
        "SSH-Patator":               1,  # BRUTE_FORCE
        "DoS slowloris":             3,  # DDOS
        "DoS Slowhttptest":          3,  # DDOS
        "DoS Hulk":                  3,  # DDOS
        "DoS GoldenEye":             3,  # DDOS
        "DDoS":                      3,  # DDOS
        "PortScan":                  2,  # PORT_SCAN
        "Bot":                       4,  # LATERAL_MOVEMENT
        "Infiltration":              4,  # LATERAL_MOVEMENT
        "Web Attack – Brute Force":  1,  # BRUTE_FORCE
        "Web Attack – XSS":          5,  # DATA_EXFILTRATION
        "Web Attack – Sql Injection": 5, # DATA_EXFILTRATION
        "Heartbleed":                6,  # PRIVILEGE_ESCALATION
    }

    # Remove linhas com labels desconhecidos
    df = df[df["Label"].isin(mapa_labels.keys())].copy()
    labels = df["Label"].map(mapa_labels)

    # Remove a coluna de label das features
    features = df.drop(columns=["Label"])

    # Remove colunas com valores infinitos ou todos NaN
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.dropna(axis=1, how="all")
    features = features.fillna(0)

    logger.info(
        f"Dataset carregado: {len(df)} amostras, "
        f"{features.shape[1]} features, "
        f"{labels.nunique()} classes."
    )

    return features, labels


def gerar_dados_sinteticos(n_amostras: int = 10_000) -> list[dict]:
    """
    Gera eventos sintéticos para treinamento quando não há dados reais.
    Útil para testar o pipeline antes de ter dados coletados.

    Args:
        n_amostras: Número de eventos a gerar.

    Returns:
        Lista de dicionários simulando eventos normais.
    """
    logger.warning(
        "Usando dados sintéticos para treinamento. "
        "Para produção, use dados reais do Elasticsearch ou CICIDS2017."
    )

    np.random.seed(42)
    eventos = []

    for _ in range(n_amostras):
        eventos.append({
            "timestamp":      pd.Timestamp.now().isoformat(),
            "event_type":     np.random.choice(["auth_success", "network_connection", "http_request"], p=[0.3, 0.5, 0.2]),
            "count":          int(np.random.normal(10, 5).clip(1, 50)),
            "bytes_sent":     int(np.random.exponential(1000).clip(0, 100_000)),
            "bytes_received": int(np.random.exponential(5000).clip(0, 500_000)),
            "duration_ms":    float(np.random.exponential(200).clip(0, 10_000)),
            "protocol":       np.random.choice(["TCP", "UDP", "ICMP"], p=[0.7, 0.2, 0.1]),
            "category":       np.random.choice(["authentication", "network", "application"], p=[0.3, 0.5, 0.2]),
            "http_status":    int(np.random.choice([200, 301, 404, 500], p=[0.8, 0.1, 0.08, 0.02])),
        })

    return eventos


# =============================================================
# Pipeline de treinamento
# =============================================================

def treinar_detector_anomalias(eventos: list[dict]) -> tuple[Preprocessor, AnomalyDetector]:
    """
    Treina o pré-processador e o detector de anomalias.

    Args:
        eventos: Lista de eventos para baseline (comportamento normal).

    Returns:
        Tupla (preprocessor, detector) já treinados.
    """
    logger.info("=== Treinando Detector de Anomalias ===")

    preprocessor = Preprocessor()
    X = preprocessor.fit_transform(eventos)

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(X)

    # Salva artefatos
    preprocessor.salvar()
    detector.salvar()

    # Estatísticas rápidas
    scores = detector.score_anomalia(X)
    n_anomalos = (scores >= 0.7).sum()
    logger.info(
        f"Baseline: {len(eventos)} eventos | "
        f"Anomalias detectadas no treino: {n_anomalos} ({n_anomalos/len(eventos)*100:.1f}%)"
    )

    return preprocessor, detector


def treinar_classificador(preprocessor: Preprocessor) -> ThreatClassifier:
    """
    Treina o classificador de ameaças.
    Tenta carregar o CICIDS2017; se não encontrar, usa dados sintéticos.

    Args:
        preprocessor: Pré-processador já treinado (para manter consistência de features).

    Returns:
        Classificador treinado.
    """
    logger.info("=== Treinando Classificador de Ameaças ===")

    caminho_cicids = DATASETS_DIR / "CICIDS2017_sample.csv"

    if caminho_cicids.exists():
        # Treinamento com dataset real
        features_df, labels = carregar_dataset_cicids(caminho_cicids)
        X = features_df.values
        y = labels.values
    else:
        # Fallback: dados sintéticos com labels aleatórios para demonstração
        logger.warning(
            f"Dataset não encontrado em {caminho_cicids}. "
            "Usando dados sintéticos. Baixe o CICIDS2017 para resultados reais."
        )
        eventos_sinteticos = gerar_dados_sinteticos(5_000)
        X = preprocessor.transform(eventos_sinteticos)
        # Labels sintéticos: 80% normal, 20% distribuído entre ataques
        y = np.random.choice(
            list(CLASSES_AMEACA.keys()),
            size=len(eventos_sinteticos),
            p=[0.80, 0.05, 0.04, 0.04, 0.03, 0.02, 0.02],
        )

    # Divide em treino e teste (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    classifier = ThreatClassifier(n_estimators=200)
    classifier.fit(X_train, y_train)

    # Avaliação no conjunto de teste
    relatorio = classifier.avaliar(X_test, y_test)
    logger.info(f"Métricas no conjunto de teste:\n{relatorio}")

    classifier.salvar()
    return classifier


# =============================================================
# Ponto de entrada
# =============================================================

def main() -> None:
    """Executa o pipeline completo de treinamento."""
    logger.info("AI-Powered Threat Hunter — Iniciando treinamento dos modelos")

    # Tenta carregar dados reais; usa sintéticos como fallback
    try:
        eventos = carregar_eventos_elasticsearch()
        if len(eventos) < 1_000:
            logger.warning(
                f"Apenas {len(eventos)} eventos no Elasticsearch. "
                "Complementando com dados sintéticos para baseline adequado."
            )
            eventos += gerar_dados_sinteticos(10_000 - len(eventos))
    except Exception as erro:
        logger.warning(f"Elasticsearch indisponível ({erro}). Usando dados sintéticos.")
        eventos = gerar_dados_sinteticos(10_000)

    # Treina os modelos
    preprocessor, detector = treinar_detector_anomalias(eventos)
    classifier = treinar_classificador(preprocessor)

    logger.info(
        f"Treinamento concluído. Artefatos salvos em: {ARTIFACTS_DIR}\n"
        f"  - preprocessor.joblib\n"
        f"  - anomaly_detector.joblib\n"
        f"  - threat_classifier.joblib"
    )


if __name__ == "__main__":
    main()
