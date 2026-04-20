# Arquitetura do Sistema

## Visão Geral

O AI-Powered Threat Hunter é composto por 6 camadas encadeadas:

```
[Rede/Sistema] → [Coleta] → [Normalização] → [ML] → [Agente LLM] → [Resposta + Relatório]
```

---

## Camadas

### 1. Coleta (`collector/`)

Responsável por capturar eventos de três fontes:

| Fonte | Ferramenta | Dados coletados |
|---|---|---|
| Tráfego de rede | Zeek / Suricata | IPs, portas, protocolos, volume, duração |
| Sistema operacional | `log_collector.py` | Auth, sudo, processos, arquivos |
| Aplicação | Logstash HTTP input | Erros HTTP, SQL Injection, APIs |

O `log_collector.py` monitora arquivos de log em tempo real (comportamento de `tail -f`) e envia cada evento normalizado para o Logstash via TCP.

---

### 2. Normalização (`docker/logstash/`)

O Logstash recebe eventos em formatos heterogêneos e os transforma no schema padrão:

```json
{
  "timestamp":      "2026-04-19T14:32:01Z",
  "event_type":     "auth_failure",
  "source_ip":      "203.0.113.5",
  "count":          847,
  "category":       "authentication",
  "severity":       null,
  "ml_score":       -1,
  "agent_analyzed": false
}
```

Campos `severity` e `ml_score` chegam nulos — são preenchidos pelo pipeline de ML.

---

### 3. Machine Learning (`ml/`)

Dois modelos trabalham em sequência:

```
Evento → Preprocessor → [Isolation Forest] → score_anomalia (0-1)
                      → [Random Forest]    → classe_ameaca + probabilidades
                      → RiskScorer         → score_final (0-100)
```

**Isolation Forest** (não supervisionado):
- Aprende o baseline de comportamento normal (7-14 dias)
- Detecta qualquer desvio sem precisar de exemplos rotulados

**Random Forest** (supervisionado):
- Treinado com CICIDS2017 / NSL-KDD
- Classifica o tipo de ataque com probabilidade por classe

**RiskScorer**:
- Combina os dois modelos: `score = anomalia * 0.35 + severidade_classe * 0.65`
- Thresholds: INFO (0-20) → BAIXO (20-40) → MEDIO (40-60) → ALTO (60-80) → CRITICO (80-100)

---

### 4. Agente LLM (`agent/`)

Ativado para alertas com score ≥ 60. Recebe o contexto completo do incidente e:

- Correlaciona eventos dos últimos 10 minutos do mesmo host
- Verifica histórico do IP de origem
- Mapeia no framework MITRE ATT&CK
- Gera relatório narrativo de incidente

---

### 5. Resposta Automática (`response/`)

Ativada para alertas com score ≥ 80 (CRITICO):

- Bloqueia IP via `iptables` / `nftables`
- Isola host da rede
- Envia notificação (Slack / Telegram / e-mail)
- Cria ticket no sistema de gestão

Tempo médio de resposta: **< 30 segundos** após detecção.

---

### 6. Dashboard (`dashboard/`)

- Kibana para visualização dos índices `threat-events-*`
- Interface própria para gestão de incidentes e status das respostas

---

## Fluxo de Dados Detalhado

```
auth.log / syslog
      │
      ▼
log_collector.py ──TCP──► Logstash :5044
                                │
                          Normalização
                          + Enriquecimento
                          + GeoIP
                                │
                                ▼
                        Elasticsearch
                        threat-events-*
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
            Isolation Forest         Random Forest
            (anomalia 0-1)      (classe + probabilidade)
                    └───────────┬───────────┘
                                ▼
                          RiskScorer
                          (score 0-100)
                                │
                   ┌────────────┼────────────┐
                   ▼            ▼            ▼
              score < 40   score 40-80   score > 80
              Log apenas   Agente LLM   Resposta
                           + Relatório  Automática
```

---

## Decisões de Design

**Por que Isolation Forest para anomalias?**
Não requer dados rotulados de ataques — funciona desde o primeiro dia com apenas tráfego normal. Eficiente em alta dimensionalidade e robusto a dados desbalanceados.

**Por que Random Forest para classificação?**
Interpretável (feature importance), robusto a overfitting com `max_depth`, e `class_weight="balanced"` compensa o desbalanceamento natural entre classes de ataque.

**Por que separar os dois modelos?**
O Isolation Forest detecta o *que é diferente*. O Random Forest classifica *o que é*. Juntos cobrem tanto ataques conhecidos quanto comportamentos nunca vistos antes.
