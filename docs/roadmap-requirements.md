# Requirements Document

## Introduction

O AI-Powered Threat Hunter é um sistema de segurança defensiva autônomo estruturado em 6 camadas encadeadas. As camadas 1 (Coleta), 2 (Normalização) e 3 (Machine Learning) estão implementadas e testadas. Este documento especifica os requisitos funcionais e de qualidade para todas as 6 camadas, com ênfase nas camadas 4 (Agente LLM), 5 (Resposta Automática) e 6 (Dashboard), que ainda precisam ser construídas.

O objetivo é fornecer critérios de aceite objetivos e verificáveis para cada entrega, garantindo que cada camada possa ser desenvolvida, testada e integrada de forma independente.

## Glossary

- **System**: O AI-Powered Threat Hunter como um todo
- **Collector**: O módulo `log_collector.py` responsável pela coleta de logs (Camada 1)
- **Normalizer**: O pipeline Logstash responsável pela normalização de eventos (Camada 2)
- **ML_Pipeline**: O conjunto de componentes de Machine Learning — Preprocessor, AnomalyDetector, ThreatClassifier e RiskScorer (Camada 3)
- **Preprocessor**: Componente que transforma eventos brutos em vetores numéricos para os modelos ML
- **AnomalyDetector**: Componente Isolation Forest que calcula score de anomalia (0.0–1.0)
- **ThreatClassifier**: Componente Random Forest que classifica o tipo de ameaça
- **RiskScorer**: Componente que combina scores de anomalia e classificação em score final (0–100)
- **ContextBuilder**: Componente que busca contexto histórico no Elasticsearch para enriquecer alertas
- **MITREMapper**: Componente que mapeia classes de ameaça para técnicas do framework MITRE ATT&CK
- **LLMAgent**: Componente que usa LLM (Claude/GPT-4) para investigar incidentes e gerar relatórios narrativos
- **ReportGenerator**: Componente que estrutura o relatório final de incidente
- **FirewallManager**: Componente que gerencia regras de bloqueio de IP via iptables/nftables
- **IsolationManager**: Componente que isola hosts comprometidos da rede
- **NotificationDispatcher**: Componente que envia notificações via Slack, Telegram e e-mail
- **ResponseOrchestrator**: Componente que orquestra todas as ações de resposta automática
- **DashboardAPI**: Backend FastAPI que expõe endpoints REST e WebSocket para o dashboard
- **DashboardUI**: Frontend React que exibe incidentes e status do sistema em tempo real
- **ThreatContext**: Estrutura de dados contendo evento atual, eventos correlacionados e histórico do IP
- **IncidentReport**: Estrutura de dados contendo o relatório completo de um incidente investigado pelo LLM
- **ResponseAction**: Estrutura de dados representando uma ação de resposta executada (sucesso ou falha)
- **ResultadoScore**: Estrutura de dados retornada pelo RiskScorer com score, severidade e flags de roteamento
- **EventoBruto**: Evento no schema de saída do Collector (Camada 1 → Camada 2)
- **EventoNormalizado**: Evento no schema do Elasticsearch após processamento pelo Normalizer
- **EventoScorado**: Evento enriquecido com campos ML após processamento pelo ML_Pipeline
- **MITRE_ATT&CK**: Framework de táticas e técnicas de ataque cibernético mantido pela MITRE Corporation
- **THRESHOLD_CRITICO**: Score >= 80 — aciona resposta automática imediata
- **THRESHOLD_ALTO**: Score >= 60 — aciona investigação pelo LLMAgent
- **INC-YYYY-NNNN**: Formato de identificador único de incidente (ex: INC-2026-0042)

---

## Requirements

### Requirement 1: Coleta e Normalização de Eventos de Log

**User Story:** As a security analyst, I want the system to continuously collect and normalize log events from multiple sources, so that all security-relevant data is available in a unified format for analysis.

#### Acceptance Criteria

1. WHEN a log line matching a known pattern is received, THE Collector SHALL parse it and return a dict containing all mandatory fields: `timestamp`, `event_type`, `source`, `raw_log`, `severity`, and `ml_score`
2. WHEN a log line does not match any known pattern, THE Collector SHALL return `None` without raising an exception
3. WHEN the TCP connection to Logstash is lost, THE Collector SHALL automatically reconnect using exponential backoff with a maximum wait of 60 seconds
4. WHEN an event is sent via TCP to Logstash, THE Normalizer SHALL index it in Elasticsearch under the `threat-events-YYYY.MM.dd` index within 5 seconds
5. WHEN an event with `count > 100` and `event_type = auth_failure` is processed, THE Normalizer SHALL add the tag `brute_force_candidate` to the indexed document
6. WHEN an event with `bytes_sent > 10485760` (10 MB) is processed, THE Normalizer SHALL add the tag `data_exfiltration_candidate` to the indexed document
7. THE Normalizer SHALL produce documents in Elasticsearch containing all mandatory fields: `@timestamp`, `event_type`, `category`, `severity`, `ml_score`, and `agent_analyzed`

---

### Requirement 2: Pipeline de Machine Learning — Pré-processamento e Detecção

**User Story:** As a security analyst, I want the ML pipeline to score every normalized event for anomaly and threat classification, so that high-risk events are automatically identified and routed for further investigation.

#### Acceptance Criteria

1. WHEN `fit()` has been called, THE Preprocessor SHALL transform a list of event dicts into a numpy array with consistent shape across calls with the same feature set
2. WHEN `score_anomalia()` is called with a valid feature matrix, THE AnomalyDetector SHALL return an array of float values where every value is in the range [0.0, 1.0]
3. WHEN `predict()` is called with a valid feature matrix, THE ThreatClassifier SHALL return a list of class name strings from the set: `{NORMAL, BRUTE_FORCE, PORT_SCAN, DDOS, LATERAL_MOVEMENT, DATA_EXFILTRATION, PRIVILEGE_ESCALATION}`
4. WHEN `calcular()` is called with a valid event dict and feature matrix, THE RiskScorer SHALL return a ResultadoScore where `score` is in the range [0.0, 100.0]
5. WHEN `score >= 80`, THE RiskScorer SHALL set `requer_resposta_automatica = True` and `requer_investigacao_llm = True` in the returned ResultadoScore
6. WHEN `score >= 60` and `score < 80`, THE RiskScorer SHALL set `requer_resposta_automatica = False` and `requer_investigacao_llm = True` in the returned ResultadoScore
7. WHEN `score < 60`, THE RiskScorer SHALL set `requer_resposta_automatica = False` and `requer_investigacao_llm = False` in the returned ResultadoScore
8. IF `fit()` has not been called before `predict()` or `transform()`, THEN THE ML_Pipeline SHALL raise a `RuntimeError` with a descriptive message indicating the model is not trained

---

### Requirement 3: Construção de Contexto para Investigação (ContextBuilder)

**User Story:** As a security analyst, I want the system to automatically gather historical context for each high-risk event, so that the LLM agent has sufficient information to conduct a meaningful investigation.

#### Acceptance Criteria

1. WHEN `construir()` is called with a valid event and score, THE ContextBuilder SHALL return a ThreatContext containing `eventos_correlacionados` with events from the same `source_ip` in the last 10 minutes
2. WHEN `construir()` is called with a valid event and score, THE ContextBuilder SHALL return a ThreatContext containing `historico_ip` with events from the same `source_ip` in the last 30 days
3. IF Elasticsearch is unavailable during context construction, THEN THE ContextBuilder SHALL return a ThreatContext with `eventos_correlacionados = []` and `historico_ip = []` without raising an exception
4. WHEN `construir()` is called, THE ContextBuilder SHALL complete and return within 2 seconds regardless of Elasticsearch response time
5. WHEN `construir()` is called with an event that has no `source_ip` field, THE ContextBuilder SHALL return a valid ThreatContext with empty correlation lists without raising an exception

---

### Requirement 4: Mapeamento MITRE ATT&CK (MITREMapper)

**User Story:** As a security analyst, I want every detected threat to be mapped to the MITRE ATT&CK framework, so that I can understand the attack technique and tactic being used.

#### Acceptance Criteria

1. WHEN `mapear()` is called with `classe_ameaca = "BRUTE_FORCE"`, THE MITREMapper SHALL return a list containing `"T1110"`
2. WHEN `mapear()` is called with `classe_ameaca = "PORT_SCAN"`, THE MITREMapper SHALL return a list containing `"T1046"`
3. WHEN `mapear()` is called with `classe_ameaca = "DATA_EXFILTRATION"`, THE MITREMapper SHALL return a list containing `"T1041"`
4. WHEN `mapear()` is called with `classe_ameaca = "PRIVILEGE_ESCALATION"`, THE MITREMapper SHALL return a list containing `"T1068"`
5. WHEN `mapear()` is called with `classe_ameaca = "LATERAL_MOVEMENT"`, THE MITREMapper SHALL return a list containing `"T1021"`
6. WHEN `mapear()` is called with `classe_ameaca = "DDOS"`, THE MITREMapper SHALL return a list containing `"T1498"`
7. IF `mapear()` is called with an unrecognized `classe_ameaca`, THEN THE MITREMapper SHALL return an empty list without raising an exception

---

### Requirement 5: Investigação por Agente LLM (LLMAgent)

**User Story:** As a security analyst, I want the LLM agent to investigate high-risk events and produce structured incident reports, so that I can quickly understand what happened and what actions to take.

#### Acceptance Criteria

1. WHEN `investigar()` is called with a valid ThreatContext, THE LLMAgent SHALL return an IncidentReport containing non-empty values for `incident_id`, `resumo`, `linha_do_tempo`, and `tecnicas_mitre`
2. WHEN `investigar()` is called, THE LLMAgent SHALL return an IncidentReport where `incident_id` matches the format `INC-YYYY-NNNN`
3. WHEN `investigar()` is called, THE LLMAgent SHALL return an IncidentReport where `confianca` is in the range [0.0, 1.0]
4. IF the LLM API call fails after 3 retry attempts, THEN THE LLMAgent SHALL return an IncidentReport with `confianca = 0.0` and a `resumo` containing an error message, without raising an exception
5. WHEN `investigar()` is called, THE LLMAgent SHALL complete within 90 seconds (3 attempts × 30 seconds timeout each)
6. WHEN `investigar()` is called with a ThreatContext containing `eventos_correlacionados`, THE LLMAgent SHALL include those events in the `linha_do_tempo` of the returned IncidentReport ordered by timestamp

---

### Requirement 6: Geração de Relatório de Incidente (ReportGenerator)

**User Story:** As a security analyst, I want incident reports to be structured, complete, and persisted, so that I can review them later and track the history of security events.

#### Acceptance Criteria

1. WHEN an IncidentReport is generated, THE ReportGenerator SHALL persist it to Elasticsearch under the `incidents` index
2. WHEN an IncidentReport is generated, THE ReportGenerator SHALL include `acoes_recomendadas` as a non-empty list of actionable strings
3. WHEN an IncidentReport is generated, THE ReportGenerator SHALL include `impacto_estimado` as a non-empty string describing the potential impact
4. WHEN an IncidentReport is generated for an event with `score >= 80`, THE ReportGenerator SHALL include at least one firewall block action in `acoes_recomendadas`
5. THE ReportGenerator SHALL produce IncidentReport objects where `timestamp_geracao` is a valid ISO 8601 UTC timestamp

---

### Requirement 7: Bloqueio de IP via Firewall (FirewallManager)

**User Story:** As a security operator, I want the system to automatically block malicious IPs at the firewall level, so that ongoing attacks are stopped immediately without manual intervention.

#### Acceptance Criteria

1. WHEN `bloquear_ip()` is called with a valid IPv4 address, THE FirewallManager SHALL add a DROP rule for that IP via iptables/nftables and return a ResponseAction with `status = "success"`
2. WHEN `bloquear_ip()` is called with an IP that is already blocked, THE FirewallManager SHALL return a ResponseAction with `status = "success"` without raising an exception or creating duplicate rules
3. WHEN `bloquear_ip()` is called successfully, THE FirewallManager SHALL persist the blocked IP to `/etc/threat-hunter/blocked_ips.conf` for persistence across reboots
4. WHEN `desbloquear_ip()` is called with a blocked IP, THE FirewallManager SHALL remove the DROP rule and return a ResponseAction with `status = "success"`
5. WHEN `listar_bloqueados()` is called, THE FirewallManager SHALL return a list of all currently blocked IPv4 addresses
6. IF `bloquear_ip()` fails due to insufficient permissions, THEN THE FirewallManager SHALL return a ResponseAction with `status = "failed"` and a descriptive `erro` message, without raising an exception

---

### Requirement 8: Isolamento de Host (IsolationManager)

**User Story:** As a security operator, I want the system to isolate compromised hosts from the network, so that lateral movement is prevented while the incident is being investigated.

#### Acceptance Criteria

1. WHEN `isolar_host()` is called with a valid hostname, THE IsolationManager SHALL drop all network traffic for that host except connections from the management bastion on port 22, and return a ResponseAction with `status = "success"`
2. WHEN `desfazer_isolamento()` is called with an isolated hostname, THE IsolationManager SHALL restore normal network connectivity for that host and return a ResponseAction with `status = "success"`
3. IF `isolar_host()` fails, THEN THE IsolationManager SHALL return a ResponseAction with `status = "failed"` and a descriptive `erro` message, without raising an exception
4. WHEN `desfazer_isolamento()` is called on a host that was previously isolated, THE IsolationManager SHALL restore the host to the same network state it had before isolation

---

### Requirement 9: Notificações (NotificationDispatcher)

**User Story:** As a security analyst, I want to receive real-time notifications about high-risk incidents via Slack, Telegram, and email, so that I can respond quickly even when not actively monitoring the dashboard.

#### Acceptance Criteria

1. WHEN `enviar_slack()` is called with a valid IncidentReport and webhook URL, THE NotificationDispatcher SHALL send the notification and return a ResponseAction with `status = "success"` within 5 seconds
2. WHEN `enviar_telegram()` is called with a valid IncidentReport, bot token, and chat ID, THE NotificationDispatcher SHALL send the notification and return a ResponseAction with `status = "success"` within 5 seconds
3. WHEN `enviar_email()` is called with a valid IncidentReport and recipient list, THE NotificationDispatcher SHALL send the notification and return a ResponseAction with `status = "success"` within 5 seconds
4. IF any notification channel is unavailable, THEN THE NotificationDispatcher SHALL return a ResponseAction with `status = "failed"` and a descriptive `erro` message, without raising an exception
5. WHEN a notification is sent, THE NotificationDispatcher SHALL include `incident_id`, `severidade`, `resumo`, and `acoes_recomendadas` in the notification content

---

### Requirement 10: Orquestração de Resposta Automática (ResponseOrchestrator)

**User Story:** As a security operator, I want the system to automatically execute the appropriate defensive actions based on incident severity, so that critical threats are contained immediately without requiring manual intervention.

#### Acceptance Criteria

1. WHEN `executar()` is called with an IncidentReport where `score >= 80`, THE ResponseOrchestrator SHALL execute firewall block, notification, and ticket creation actions
2. WHEN `executar()` is called with an IncidentReport where `score >= 60` and `score < 80`, THE ResponseOrchestrator SHALL execute notification and ticket creation actions without executing firewall block
3. WHEN `executar()` is called, THE ResponseOrchestrator SHALL return a list of ResponseAction objects for every action attempted, regardless of whether each action succeeded or failed
4. IF one action fails during `executar()`, THEN THE ResponseOrchestrator SHALL continue executing the remaining actions and include the failed action in the returned list with `status = "failed"`
5. WHEN `executar()` is called, THE ResponseOrchestrator SHALL complete and return within 30 seconds

---

### Requirement 11: API REST do Dashboard (DashboardAPI)

**User Story:** As a security analyst, I want a REST API to query incidents and system health, so that I can integrate the threat hunter data into other tools and workflows.

#### Acceptance Criteria

1. WHEN `GET /incidents` is called, THE DashboardAPI SHALL return a paginated JSON response with `total` and `incidents` fields within 500 milliseconds
2. WHEN `GET /incidents` is called with query parameters `severity`, `limit`, and `from`, THE DashboardAPI SHALL filter and return only incidents matching those criteria
3. WHEN `GET /incidents/{incident_id}` is called with a valid incident ID, THE DashboardAPI SHALL return the complete IncidentReport including all associated ResponseActions
4. IF `GET /incidents/{incident_id}` is called with a non-existent incident ID, THEN THE DashboardAPI SHALL return HTTP 404 with a descriptive error message
5. WHEN `POST /incidents/{incident_id}/status` is called with `status = "resolved"` or `status = "false_positive"`, THE DashboardAPI SHALL update the incident status and return HTTP 200
6. WHEN `GET /health` is called, THE DashboardAPI SHALL return the real-time status of all system components: `elasticsearch`, `logstash`, `ml_pipeline`, and `llm_agent`, each as `"up"` or `"down"`, along with a `score_saude` float

---

### Requirement 12: WebSocket para Eventos em Tempo Real (DashboardAPI)

**User Story:** As a security analyst, I want to receive real-time incident notifications in the dashboard without manual page refresh, so that I can monitor the security posture of the network continuously.

#### Acceptance Criteria

1. WHEN a client connects to `WebSocket /ws/events`, THE DashboardAPI SHALL accept the connection and begin streaming IncidentReport events
2. WHEN an IncidentReport with `score >= 60` is generated, THE DashboardAPI SHALL emit it to all connected WebSocket clients within 1 second of report generation
3. WHEN a WebSocket client disconnects, THE DashboardAPI SHALL remove the client from the active connections list without affecting other connected clients
4. WHILE a WebSocket connection is active, THE DashboardAPI SHALL maintain the connection and emit all new IncidentReport events as they are generated

---

### Requirement 13: Interface Visual do Dashboard (DashboardUI)

**User Story:** As a security analyst, I want a visual dashboard to monitor incidents, response actions, and system health in real time, so that I can quickly assess the security posture and take action when needed.

#### Acceptance Criteria

1. WHEN the dashboard loads, THE DashboardUI SHALL display the list of recent incidents fetched from `GET /incidents`
2. WHEN a new IncidentReport is received via WebSocket, THE DashboardUI SHALL add it to the incident list without requiring a manual page refresh
3. WHEN an incident is selected, THE DashboardUI SHALL display the full IncidentReport details including `linha_do_tempo`, `tecnicas_mitre`, and `acoes_recomendadas`
4. WHEN the dashboard loads, THE DashboardUI SHALL display the system health status fetched from `GET /health`
5. WHEN an analyst marks an incident as `resolved` or `false_positive`, THE DashboardUI SHALL call `POST /incidents/{incident_id}/status` and update the displayed status without a full page reload

---

### Requirement 14: Segurança e Configuração do Sistema

**User Story:** As a system administrator, I want all sensitive credentials and configurations to be managed securely, so that API keys and tokens are never exposed in source code or logs.

#### Acceptance Criteria

1. THE System SHALL read all API keys (LLM, Slack, Telegram) exclusively from environment variables, never from hardcoded values in source code
2. THE DashboardAPI SHALL require JWT authentication for all REST endpoints and WebSocket connections
3. WHEN any component logs an event, THE System SHALL not include passwords, API tokens, or other sensitive data in log output
4. WHEN the LLMAgent constructs a prompt, THE System SHALL sanitize all user-controlled data before including it in the prompt to prevent prompt injection
5. WHEN FirewallManager creates a block rule, THE System SHALL set a TTL via `duracao_segundos` parameter to prevent permanent accidental blocks

---

### Requirement 15: Contrato de Interface entre Camadas

**User Story:** As a developer, I want clear interface contracts between all system layers, so that each layer can be developed, tested, and replaced independently.

#### Acceptance Criteria

1. THE Collector SHALL produce EventoBruto dicts containing all mandatory fields before sending to the Normalizer
2. THE Normalizer SHALL produce EventoNormalizado documents in Elasticsearch containing all mandatory fields before the ML_Pipeline reads them
3. WHEN the ML_Pipeline processes an event, THE ML_Pipeline SHALL produce EventoScorado dicts containing all ML fields (`ml_score`, `ml_severidade`, `ml_classe_ameaca`, `ml_score_anomalia`, `ml_probabilidades`, `requer_investigacao_llm`, `requer_resposta_automatica`) before passing to the LLMAgent
4. WHEN the LLMAgent completes investigation, THE LLMAgent SHALL produce a complete IncidentReport before passing to the ResponseOrchestrator
5. THE ResponseOrchestrator SHALL produce a list of ResponseAction objects, one per attempted action, before returning to the caller
