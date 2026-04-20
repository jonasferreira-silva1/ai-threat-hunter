# Guia de Testes

## Estrutura

```
tests/
├── conftest.py              ← Fixtures compartilhadas entre todos os testes
├── collector/
│   └── test_log_collector.py
└── ml/
    ├── test_preprocessor.py
    ├── test_anomaly_detector.py
    ├── test_threat_classifier.py
    └── test_scorer.py
```

---

## Categorias de Testes

Os testes são marcados com categorias para execução seletiva:

| Marcador | Descrição | Requer infraestrutura? |
|---|---|---|
| `unit` | Testes isolados, sem dependências externas | Não |
| `integration` | Requerem ELK Stack rodando | Sim |
| `slow` | Demoram mais de 5 segundos | Não |

---

## Comandos

```bash
# Apenas testes unitários (recomendado para desenvolvimento)
pytest -m unit

# Todos os testes
pytest

# Testes de um módulo específico
pytest tests/ml/
pytest tests/collector/

# Com relatório de cobertura
pytest --cov=ml --cov=collector --cov-report=term-missing

# Parar no primeiro erro
pytest -x

# Verbose com detalhes de cada teste
pytest -v
```

---

## Cobertura por Módulo

| Módulo | Arquivo de teste | O que é testado |
|---|---|---|
| `collector/syslog/log_collector.py` | `test_log_collector.py` | Normalização de logs, schema padrão, serialização JSON |
| `ml/preprocessor.py` | `test_preprocessor.py` | Extração de features, fit/transform, persistência |
| `ml/anomaly_detection/detector.py` | `test_anomaly_detector.py` | Treinamento, scores, thresholds, persistência |
| `ml/threat_classifier/classifier.py` | `test_threat_classifier.py` | Predição, probabilidades, severidade, persistência |
| `ml/scorer.py` | `test_scorer.py` | Score final, thresholds, flags de ação, lote |

---

## Fixtures Disponíveis

Definidas em `tests/conftest.py` e disponíveis em todos os testes:

| Fixture | Descrição |
|---|---|
| `evento_auth_failure` | Evento de brute force SSH (847 tentativas) |
| `evento_auth_success` | Login bem-sucedido após falhas |
| `evento_network_normal` | Tráfego de rede dentro do padrão |
| `evento_exfiltracao` | 50 MB enviados para IP externo |
| `evento_sql_injection` | Requisição com payload `OR 1=1` |
| `lista_eventos_normais` | 100 eventos normais para treinamento |
| `vetor_features_simples` | Array numpy pré-processado para testes rápidos |
| `matriz_features_lote` | Matriz de features para testes em lote |

---

## Adicionando Novos Testes

1. Crie o arquivo em `tests/<módulo>/test_<nome>.py`
2. Importe as fixtures necessárias do `conftest.py` (automático pelo pytest)
3. Marque cada teste com `@pytest.mark.unit` ou `@pytest.mark.integration`
4. Siga o padrão de nomenclatura: `test_<o_que_testa>_<comportamento_esperado>`

Exemplo:
```python
@pytest.mark.unit
def test_score_anomalia_retorna_zero_para_evento_normal(detector_treinado):
    detector, preprocessor = detector_treinado
    # ...
```
