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

---

## Como Funciona: As 6 Camadas

### 📡 Camada 1 — Coleta de Dados

Três fontes simultâneas alimentam o sistema:

- **Tráfego de rede** via Zeek/Suricata — IPs, portas, protocolos, volume, duração de conexões
- **Logs do sistema operacional** — autenticação, processos, arquivos modificados, escalonamento de privilégios
- **Logs de aplicação** — erros HTTP, tentativas de SQL Injection, requisições malformadas

Tudo centralizado no **Elasticsearch** via **Logstash**.

---

### ⚙️ Camada 2 — Normalização

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

### 🤖 Camada 3 — Detecção por Machine Learning

Dois modelos trabalham em paralelo:

**Modelo 1 — Detecção de Anomalias (Não Supervisionado)**
- Algoritmo: Isolation Forest / Autoencoder
- Aprende o comportamento normal da rede durante 7-14 dias
- Qualquer desvio gera alerta — detecta o que regras fixas nunca pegariam

**Modelo 2 — Classificação de Ameaças (Supervisionado)**
- Algoritmo: Random Forest / XGBoost
- Treinado com datasets reais: NSL-KDD, CICIDS2017
- Classifica: Brute Force, Port Scanning, DDoS, Lateral Movement, Data Exfiltration, Privilege Escalation

Juntos, geram um **score de risco de 0 a 100** para cada evento.

---

### 🧠 Camada 4 — Agente LLM (O Diferencial)

Quando um alerta com score alto é gerado, um agente LLM (Claude/GPT-4) recebe o contexto completo e conduz uma investigação:

```
🚨 INCIDENTE #2024-042 — SEVERIDADE: CRÍTICA

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

### ⚡ Camada 5 — Resposta Automática

Para alertas críticos, o sistema age antes do analista ler o relatório:

- Bloqueia IPs maliciosos via iptables/nftables
- Isola o host comprometido da rede
- Envia notificação via Slack/Telegram/e-mail
- Cria ticket automático no sistema de gestão

**Tudo em menos de 30 segundos após a detecção.**

---

### 📊 Camada 6 — Dashboard

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
| Captura de tráfego | Zeek / Suricata |
| Ingestão de logs | Logstash |
| Armazenamento | Elasticsearch |
| Visualização | Kibana |
| Machine Learning | scikit-learn, XGBoost |
| Agente LLM | Claude API / OpenAI GPT-4 |
| Resposta automática | Python + iptables/nftables |
| Notificações | Slack API / Telegram Bot |
| Infraestrutura | Docker + Docker Compose |
| Laboratório | VMs Linux/Windows + Kali Linux |

---

## Estrutura do Repositório

```
ai-threat-hunter/
├── docker/                  # Docker Compose e configurações de infraestrutura
│   ├── docker-compose.yml
│   ├── elasticsearch/
│   ├── logstash/
│   └── kibana/
├── collector/               # Agentes de coleta de dados
│   ├── zeek/
│   ├── suricata/
│   └── syslog/
├── ml/                      # Modelos de Machine Learning
│   ├── anomaly_detection/
│   ├── threat_classifier/
│   └── datasets/
├── agent/                   # Agente LLM de investigação
│   ├── llm_agent.py
│   ├── prompts/
│   └── mitre/
├── response/                # Módulo de resposta automática
│   ├── firewall.py
│   ├── isolation.py
│   └── notifications.py
├── dashboard/               # Interface web própria
│   ├── frontend/
│   └── backend/
├── lab/                     # Scripts do laboratório de simulação
│   ├── attacker/
│   └── victim/
├── docs/                    # Documentação técnica
└── README.md
```

---

## Laboratório de Demonstração

O projeto inclui um laboratório virtual completo para demonstração:

- **Rede vítima** — VMs com Linux/Windows simulando uma empresa real
- **Máquina atacante** — Kali Linux executando ataques reais (Nmap, Hydra, Metasploit)
- **Sistema de defesa** — O Threat Hunter rodando e reagindo em tempo real

---

## Como Rodar

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/ai-threat-hunter.git
cd ai-threat-hunter

# Suba a infraestrutura
docker-compose -f docker/docker-compose.yml up -d

# Verifique os serviços
docker-compose ps

# Acesse o Kibana
# http://localhost:5601
```

---

## Roadmap

| Semana | Entrega |
|---|---|
| 1-2 | Ambiente de laboratório + coleta de logs funcionando |
| 3-4 | Pipeline ELK configurado e dados fluindo |
| 5-6 | Modelo ML treinado e detectando anomalias |
| 7-8 | Integração do agente LLM + geração de relatórios |
| 9-10 | Resposta automática + dashboard |
| 11-12 | Simulações de ataque + documentação final |

---

## Por que Este Projeto é Diferente

A maioria dos portfólios de segurança tem scanners de senha e packet sniffers básicos.

Este projeto combina quatro áreas valorizadas simultaneamente:

- **Segurança defensiva** — detecção e resposta a incidentes reais
- **Machine Learning** — modelos supervisionados e não supervisionados
- **LLMs aplicados** — agente investigativo com raciocínio contextual
- **Automação de resposta** — ação autônoma em menos de 30 segundos

Exatamente o perfil que o mercado de 2026 está contratando.

---

## Métricas Esperadas

- Tempo médio de detecção: **< 60 segundos**
- Tempo de resposta automática: **< 30 segundos**
- Taxa de falsos positivos: **< 5%** (após período de aprendizado)
- Cobertura MITRE ATT&CK: **15+ técnicas mapeadas**

---

*Construído para o mercado de segurança de 2026 — onde detecção sem inteligência já não é suficiente.*
