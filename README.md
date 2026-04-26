# 🛡️ AI-Powered Threat Hunter

> *"Em 2023, uma empresa de saúde ficou 47 dias com um atacante dentro da sua rede antes de alguém perceber. Quarenta e sete dias. O atacante tinha acesso a prontuários de 11 milhões de pacientes. A equipe de segurança recebia alertas — centenas deles por dia — mas não tinha como analisar tudo."*

Esse caso não é exceção. É a regra.

---

## O Problema que Ninguém Consegue Resolver Sozinho

O mercado de segurança enfrenta uma crise silenciosa: existe uma escassez global de mais de **3,5 milhões de profissionais de cibersegurança**. As empresas que conseguem contratar analistas os sobrecarregam com um volume absurdo de alertas — a maioria falsos positivos — até o ponto em que o profissional começa a ignorar notificações. É o fenômeno chamado de *alert fatigue*.

O resultado? Ataques reais passam despercebidos por semanas.

As ferramentas tradicionais de segurança — SIEMs, IDS, firewalls — são boas em **detectar**. Mas detecção sem contexto é ruído. Um analista sênior não apenas vê o alerta: ele investiga, correlaciona eventos, entende a intenção do atacante e age. Esse raciocínio investigativo é o que falta nas ferramentas convencionais.

---

## A Pergunta que Mudou Tudo

*"O que um analista sênior de segurança faz que uma ferramenta automatizada não consegue?"*

Ele **pensa**. Ele pergunta: *esse IP já apareceu antes? Esse comportamento é normal para esse usuário? O que aconteceu nos 10 minutos anteriores a esse evento? Isso se encaixa em algum padrão de ataque conhecido?*

Foi essa pergunta que originou o **AI-Powered Threat Hunter**.

---

## O que Este Projeto É

Um sistema de segurança defensiva autônomo que age como um **analista sênior automatizado**, rodando 24/7, sem fadiga, sem pausas.

Ele não apenas detecta — ele **investiga, entende, explica e age**.

```
[Rede/Sistema] → [Coleta] → [Processamento] → [IA Detecta] → [Agente Analisa] → [Ação + Relatório]
```

> ✅ **Camadas 1–4 implementadas e testadas** — pipeline completo de coleta, normalização, ML e agente LLM funcionando com 66+ testes automatizados passando.
> 🔧 **Camadas 5–6 em desenvolvimento ativo** — resposta automática e dashboard.

---

## Como Funciona: As 6 Camadas

### 📡 Camada 1 — Coleta de Dados ✅

Três fontes simultâneas alimentam o sistema:

- **Tráfego de rede** via Zeek/Suricata — IPs, portas, protocolos, volume, duração de conexões
- **Logs do sistema operacional** — autenticação, processos, arquivos modificados, escalonamento de privilégios
- **Logs de aplicação** — erros HTTP, tentativas de SQL Injection, requisições malformadas

Tudo centralizado no **Elasticsearch** via **Logstash**.

---

### ⚙️ Camada 2 — Normalização ✅

Dados de fontes diferentes chegam em formatos diferentes. O Logstash transforma tudo num padrão unificado:

```json
{
  "timestamp": "2026-04-19T14:32:01Z",
  "source_ip": "192.168.1.50",
  "event_type": "auth_failure",
  "count": 847,
  "severity": null
}
```

Limpos e prontos para a IA analisar.

---

### 🤖 Camada 3 — Detecção por Machine Learning ✅

Dois modelos trabalham em paralelo:

**Modelo 1 — Detecção de Anomalias (Não Supervisionado)**
- Algoritmo: Isolation Forest
- Aprende o comportamento normal da rede durante 7-14 dias
- Qualquer desvio gera alerta — detecta o que regras fixas nunca pegariam

**Modelo 2 — Classificação de Ameaças (Supervisionado)**
- Algoritmo: Random Forest
- Treinado com datasets reais: CICIDS2017
- Classifica: Brute Force, Port Scanning, DDoS, Lateral Movement, Data Exfiltration, Privilege Escalation

Juntos, geram um **score de risco de 0 a 100** para cada evento.

---

### 🧠 Camada 4 — Agente LLM (O Diferencial) ✅

Quando um alerta com score alto é gerado, um agente LLM (Claude/GPT-4) recebe o contexto completo e conduz uma investigação:

```
🚨 INCIDENTE #2026-042 — SEVERIDADE: CRÍTICA

RESUMO: Possível ataque de Brute Force seguido de escalonamento de privilégio.

LINHA DO TEMPO:
  14:30 — 847 tentativas de login SSH falhas do IP 203.0.113.5
  14:32 — Login bem-sucedido com usuário "deploy"
  14:33 — Execução de "sudo su" pelo mesmo usuário

IMPACTO ESTIMADO: Acesso root potencial ao servidor web-01

AÇÃO RECOMENDADA:
  1. Bloquear IP 203.0.113.5 imediatamente
  2. Revogar sessão do usuário "deploy"
  3. Auditar comandos executados após 14:32

MAPEAMENTO MITRE ATT&CK:
  T1110 (Brute Force) → T1078 (Valid Accounts)
```

---

### ⚡ Camada 5 — Resposta Automática 🔧 Em desenvolvimento

Para alertas críticos, o sistema age antes do analista ler o relatório:

- Bloqueia IPs maliciosos via iptables/nftables
- Isola o host comprometido da rede
- Envia notificação via Slack/Telegram/e-mail
- Cria ticket automático no sistema de gestão

**Tudo em menos de 30 segundos após a detecção.**

---

### 📊 Camada 6 — Dashboard 🔧 Em desenvolvimento

Kibana + interface própria para supervisão humana:

- Mapa de calor de eventos por horário
- Gráfico de ameaças por tipo e severidade
- Timeline de cada incidente
- Status das respostas automáticas
- Score de saúde geral da rede

---

## Stack Tecnológica

| Camada | Tecnologia |
|---|---|
| Captura de logs | Python (syslog collector) |
| Ingestão e normalização | Logstash |
| Armazenamento | Elasticsearch |
| Visualização | Kibana |
| Machine Learning | scikit-learn (Isolation Forest + Random Forest) |
| Agente LLM | Anthropic Claude API / OpenAI GPT-4 |
| Resposta automática | Python + iptables/nftables |
| Notificações | Slack API / Telegram Bot |
| Infraestrutura | Docker + Docker Compose |
| Testes | pytest + Hypothesis (property-based testing) |

---

## Estrutura do Repositório

```
ai-threat-hunter/
├── docker/                        # Infraestrutura ELK Stack
│   ├── docker-compose.yml
│   ├── elasticsearch/
│   ├── logstash/
│   │   └── pipeline/logstash.conf
│   └── kibana/
├── collector/                     # Camada 1 — Coleta de logs
│   └── syslog/
│       └── log_collector.py
├── ml/                            # Camada 3 — Machine Learning
│   ├── anomaly_detection/
│   │   └── detector.py            # Isolation Forest
│   ├── threat_classifier/
│   │   └── classifier.py          # Random Forest
│   ├── preprocessor.py
│   ├── scorer.py                  # Score de risco 0-100
│   └── trainer.py
├── agent/                         # Camada 4 — Agente LLM
│   ├── context_builder.py         # Busca contexto no Elasticsearch
│   ├── mitre_mapper.py            # Mapeamento MITRE ATT&CK
│   ├── llm_agent.py               # Orquestrador Claude/GPT-4
│   ├── report_generator.py        # Geração do relatório de incidente
│   └── prompts/                   # Templates de prompt
├── response/                      # Camada 5 — Resposta automática
│   ├── firewall.py                # (em desenvolvimento)
│   ├── isolation.py               # (em desenvolvimento)
│   ├── notifications.py           # (em desenvolvimento)
│   └── orchestrator.py            # (em desenvolvimento)
├── dashboard/                     # Camada 6 — Dashboard
│   ├── backend/                   # (em desenvolvimento)
│   └── frontend/                  # (em desenvolvimento)
├── tests/                         # Testes automatizados
│   ├── collector/
│   ├── ml/
│   ├── agent/
│   └── response/
├── docs/                          # Documentação técnica
│   ├── arquitetura.md
│   ├── roadmap-design.md
│   ├── roadmap-requirements.md
│   └── roadmap-tasks.md
└── README.md
```

---

## Como Rodar

### Pré-requisitos

- Docker e Docker Compose instalados
- Python 3.11+
- Chave de API Anthropic ou OpenAI (para o agente LLM)

### 1. Suba a infraestrutura

```bash
git clone https://github.com/seu-usuario/ai-threat-hunter.git
cd ai-threat-hunter

docker-compose -f docker/docker-compose.yml up -d

# Verifique os serviços
docker-compose -f docker/docker-compose.yml ps

# Acesse o Kibana em http://localhost:5601
```

### 2. Instale as dependências Python

```bash
pip install -r ml/requirements.txt
pip install anthropic hypothesis pytest
```

### 3. Configure as variáveis de ambiente

```bash
# Copie o arquivo de exemplo e preencha suas credenciais
cp .env.example .env
# Edite o .env com ANTHROPIC_API_KEY, ELASTIC_HOST, etc.
```

### 4. Treine os modelos de ML

```bash
# Treina com dados sintéticos (fallback automático sem Elasticsearch)
python -m ml.trainer
```

### 5. Rode os testes

```bash
# Todos os testes
pytest

# Apenas testes unitários
pytest -m unit

# Testes de uma camada específica
pytest tests/ml/
pytest tests/agent/
```

---

## Status do Projeto

| Camada | Status | Testes |
|---|---|---|
| 1 — Coleta de logs | ✅ Completo | ✅ |
| 2 — Normalização ELK | ✅ Completo | ✅ |
| 3 — Machine Learning | ✅ Completo | ✅ |
| 4 — Agente LLM | ✅ Completo | ✅ |
| 5 — Resposta Automática | 🔧 Em desenvolvimento | 🔧 |
| 6 — Dashboard | 🔧 Em desenvolvimento | 🔧 |

---

## Por que Este Projeto é Diferente

A maioria dos portfólios de segurança tem scanners de senha e packet sniffers básicos.

Este projeto combina quatro áreas valorizadas simultaneamente:

- **Segurança defensiva** — detecção e resposta a incidentes reais
- **Machine Learning** — modelos supervisionados e não supervisionados treinados com datasets reais (CICIDS2017)
- **LLMs aplicados** — agente investigativo com raciocínio contextual e mapeamento MITRE ATT&CK
- **Automação de resposta** — ação autônoma em menos de 30 segundos

Exatamente o perfil que o mercado de 2026 está contratando.

---

## Métricas Esperadas

- Tempo médio de detecção: **< 60 segundos**
- Tempo de resposta automática: **< 30 segundos**
- Taxa de falsos positivos: **< 5%** (após período de aprendizado)
- Cobertura MITRE ATT&CK: **15+ técnicas mapeadas**

---

## Documentação

- [`docs/arquitetura.md`](docs/arquitetura.md) — Arquitetura detalhada do sistema
- [`docs/roadmap-design.md`](docs/roadmap-design.md) — Design técnico completo com contratos de interface
- [`docs/roadmap-requirements.md`](docs/roadmap-requirements.md) — Requisitos e critérios de aceite
- [`docs/roadmap-tasks.md`](docs/roadmap-tasks.md) — Plano de implementação com status das tarefas

---

*Construído para o mercado de segurança de 2026 — onde detecção sem inteligência já não é suficiente.*
