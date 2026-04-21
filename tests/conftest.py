"""
Fixtures compartilhadas entre todos os testes.

conftest.py é carregado automaticamente pelo pytest antes de qualquer teste.
As fixtures aqui definidas ficam disponíveis em todos os arquivos de teste
sem necessidade de importação explícita.
"""

import pytest
import numpy as np
from datetime import datetime, timezone


# =============================================================
# Fixtures de eventos de segurança
# Simulam dados que viriam do Elasticsearch em produção
# =============================================================

@pytest.fixture
def evento_auth_failure():
    """Evento de falha de autenticação SSH — padrão de brute force."""
    return {
        "_id": "test-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "auth_failure",
        "source_ip": "203.0.113.5",
        "username": "root",
        "count": 847,
        "category": "authentication",
        "protocol": "TCP",
        "bytes_sent": 0,
        "bytes_received": 0,
        "duration_ms": 0.0,
        "http_status": 0,
        "severity": None,
        "ml_score": -1,
    }


@pytest.fixture
def evento_auth_success():
    """Evento de autenticação bem-sucedida após falhas — suspeito."""
    return {
        "_id": "test-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "auth_success",
        "source_ip": "203.0.113.5",
        "username": "deploy",
        "count": 1,
        "category": "authentication",
        "protocol": "TCP",
        "bytes_sent": 512,
        "bytes_received": 1024,
        "duration_ms": 120.0,
        "http_status": 0,
        "severity": None,
        "ml_score": -1,
    }


@pytest.fixture
def evento_network_normal():
    """Evento de tráfego de rede dentro do padrão normal."""
    return {
        "_id": "test-003",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_connection",
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "count": 5,
        "category": "network",
        "protocol": "TCP",
        "bytes_sent": 2048,
        "bytes_received": 8192,
        "duration_ms": 350.0,
        "http_status": 0,
        "severity": None,
        "ml_score": -1,
    }


@pytest.fixture
def evento_exfiltracao():
    """Evento com volume de dados anormalmente alto — possível exfiltração."""
    return {
        "_id": "test-004",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_connection",
        "source_ip": "192.168.1.50",
        "destination_ip": "203.0.113.99",
        "count": 1,
        "category": "network",
        "protocol": "TCP",
        "bytes_sent": 52_428_800,   # 50 MB enviados para IP externo
        "bytes_received": 512,
        "duration_ms": 8500.0,
        "http_status": 0,
        "severity": None,
        "ml_score": -1,
    }


@pytest.fixture
def evento_sql_injection():
    """Evento de requisição HTTP com payload de SQL Injection."""
    return {
        "_id": "test-005",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "http_request",
        "source_ip": "198.51.100.7",
        "count": 1,
        "category": "application",
        "protocol": "TCP",
        "bytes_sent": 256,
        "bytes_received": 1024,
        "duration_ms": 45.0,
        "http_status": 200,
        "request_body": "' OR 1=1 --",
        "severity": None,
        "ml_score": -1,
    }


@pytest.fixture
def lista_eventos_normais():
    """Lista de 100 eventos normais para treinamento dos modelos."""
    np.random.seed(42)
    eventos = []
    for i in range(100):
        eventos.append({
            "_id": f"normal-{i}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": np.random.choice(
                ["auth_success", "network_connection", "http_request"],
                p=[0.3, 0.5, 0.2],
            ),
            "count":          int(np.clip(np.random.normal(10, 3), 1, 30)),
            "bytes_sent":     int(np.clip(np.random.exponential(1000), 0, 50_000)),
            "bytes_received": int(np.clip(np.random.exponential(5000), 0, 100_000)),
            "duration_ms":    float(np.clip(np.random.exponential(200), 0, 5_000)),
            "protocol":       np.random.choice(["TCP", "UDP"], p=[0.8, 0.2]),
            "category":       np.random.choice(
                ["authentication", "network", "application"],
                p=[0.3, 0.5, 0.2],
            ),
            "http_status":    int(np.random.choice([200, 301, 404], p=[0.85, 0.1, 0.05])),
            "severity": None,
            "ml_score": -1,
        })
    return eventos


@pytest.fixture
def vetor_features_simples():
    """Vetor de features pré-processado para testes rápidos dos modelos."""
    # Shape (1, 10) — 7 numéricas + 3 categóricas codificadas
    return np.array([[10.0, 1000.0, 5000.0, 200.0, 14.0, 1.0, 200.0, 1.0, 0.0, 0.0]])


@pytest.fixture
def matriz_features_lote(lista_eventos_normais):
    """Matriz de features para testes em lote."""
    from ml.preprocessor import Preprocessor
    preprocessor = Preprocessor()
    return preprocessor.fit_transform(lista_eventos_normais)
