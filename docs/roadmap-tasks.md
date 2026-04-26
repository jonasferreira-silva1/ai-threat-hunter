# Implementation Plan: AI-Powered Threat Hunter — Camadas 4, 5 e 6

## Overview

Implementação incremental das três camadas restantes do AI-Powered Threat Hunter, seguindo a ordem definida no design: Camada 4 (Agente LLM) → Camada 5 (Resposta Automática) → Camada 6 (Dashboard). Cada tarefa constrói sobre a anterior e termina com integração funcional entre as camadas.

## Tasks

- [x] 1. Estrutura base da Camada 4 — Agente LLM
  - Criar `agent/__init__.py` exportando as classes públicas da camada
  - Criar `agent/prompts/investigation.txt` com o prompt de investigação de incidente
  - Criar `agent/prompts/report.txt` com o prompt de geração de relatório estruturado
  - Criar `tests/agent/__init__.py` e `tests/agent/conftest.py` com fixtures compartilhadas (mock ES, mock LLM)
  - _Requirements: 15.4_

- [x] 2. Implementar MITREMapper
  - [x] 2.1 Criar `agent/mitre_mapper.py` com a classe `MITREMapper`
    - Implementar `MAPEAMENTO` dict com todas as 6 classes de ameaça → técnicas ATT&CK
    - Implementar `mapear(classe_ameaca, contexto) -> list[str]`
    - Retornar lista vazia para classes desconhecidas sem lançar exceção
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [ ]* 2.2 Escrever testes unitários para MITREMapper
    - Testar cada uma das 6 classes conhecidas retorna a técnica correta
    - Testar classe desconhecida retorna lista vazia
    - _Requirements: 4.1–4.7_

  - [ ]* 2.3 Escrever property test para MITREMapper — classes desconhecidas
    - **Property 8: MITREMapper retorna lista vazia para classes desconhecidas**
    - Para qualquer string fora do conjunto conhecido, `mapear()` retorna `[]` sem exceção
    - **Validates: Requirements 4.7**

- [x] 3. Implementar ContextBuilder
  - [x] 3.1 Criar `agent/context_builder.py` com a classe `ContextBuilder`
    - Implementar `__init__(self, es_client: Elasticsearch)`
    - Implementar `construir(evento, score) -> ThreatContext`
    - Buscar eventos correlacionados do mesmo `source_ip` nos últimos 10 minutos (size=50)
    - Buscar histórico do `source_ip` nos últimos 30 dias (size=100)
    - Aplicar timeout de 2s nas queries ao Elasticsearch
    - Retornar `ThreatContext` com listas vazias em caso de falha do ES (nunca lançar exceção)
    - Tratar evento sem campo `source_ip` retornando contexto com listas vazias
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [ ]* 3.2 Escrever testes unitários para ContextBuilder
    - Testar busca com ES mockado retornando eventos
    - Testar fallback com ES indisponível (ConnectionError, timeout)
    - Testar evento sem `source_ip`
    - Verificar que retorno é sempre em < 2s
    - _Requirements: 3.1–3.5_

  - [ ]* 3.3 Escrever property test para ContextBuilder — resiliência ao ES
    - **Property 7: ContextBuilder é resiliente a falhas do Elasticsearch**
    - Para qualquer evento e score válidos com ES indisponível, `construir()` retorna ThreatContext com listas vazias sem exceção
    - **Validates: Requirements 3.3**

- [x] 4. Implementar LLMAgent e ReportGenerator
  - [x] 4.1 Criar `agent/report_generator.py` com a classe `ReportGenerator`
    - Implementar geração de `incident_id` no formato `INC-YYYY-NNNN` (sequencial por ano)
    - Implementar `gerar(contexto, resposta_llm) -> IncidentReport`
    - Garantir `acoes_recomendadas` como lista não-vazia
    - Garantir `impacto_estimado` como string não-vazia
    - Garantir `timestamp_geracao` como ISO 8601 UTC válido
    - Para `score >= 80`, incluir pelo menos uma ação de bloqueio de firewall em `acoes_recomendadas`
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 4.2 Criar `agent/llm_agent.py` com a classe `LLMAgent`
    - Implementar `__init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022")`
    - Implementar `investigar(contexto: ThreatContext) -> IncidentReport`
    - Montar prompt com dados do `ThreatContext` (sanitizar dados controlados pelo usuário)
    - Chamar API do LLM com timeout de 30s por tentativa
    - Implementar retry com backoff exponencial (3 tentativas)
    - Em falha total: retornar `IncidentReport` com `confianca=0.0` e `resumo` com mensagem de erro
    - Ordenar `linha_do_tempo` por timestamp crescente
    - Ler `api_key` exclusivamente de variável de ambiente (nunca hardcoded)
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 14.1, 14.4_

  - [ ]* 4.3 Escrever testes unitários para LLMAgent e ReportGenerator
    - Testar `investigar()` com mock da API retornando resposta válida
    - Testar `investigar()` com mock da API falhando 3 vezes → `confianca=0.0`
    - Testar formato do `incident_id` (regex `INC-\d{4}-\d{4}`)
    - Testar ordenação cronológica da `linha_do_tempo`
    - Testar que `acoes_recomendadas` inclui bloqueio de firewall quando `score >= 80`
    - _Requirements: 5.1–5.6, 6.2–6.5_

  - [ ]* 4.4 Escrever property test — LLMAgent sempre retorna IncidentReport válido
    - **Property 9: LLMAgent sempre retorna IncidentReport estruturalmente válido**
    - Para qualquer ThreatContext válido (LLM mockado), `investigar()` retorna IncidentReport com `incident_id` no formato correto, `confianca` em [0.0, 1.0], e campos não-nulos
    - **Validates: Requirements 5.1, 5.2, 5.3**

  - [ ]* 4.5 Escrever property test — LLMAgent resiliente a falhas da API
    - **Property 10: LLMAgent é resiliente a falhas da API LLM**
    - Para qualquer ThreatContext válido com API falhando em todas as tentativas, `investigar()` retorna IncidentReport com `confianca=0.0` sem lançar exceção
    - **Validates: Requirements 5.4**

  - [ ]* 4.6 Escrever property test — ReportGenerator produz relatórios completos
    - **Property 12: ReportGenerator produz relatórios completos e válidos**
    - Para qualquer IncidentReport gerado, `acoes_recomendadas` é lista não-vazia, `impacto_estimado` é string não-vazia, e `timestamp_geracao` é ISO 8601 UTC válido
    - **Validates: Requirements 6.2, 6.3, 6.5**

  - [ ]* 4.7 Escrever property test — ReportGenerator inclui ação de firewall para críticos
    - **Property 13: ReportGenerator inclui ação de firewall para incidentes críticos**
    - Para qualquer IncidentReport com `score >= 80`, `acoes_recomendadas` contém pelo menos uma ação de bloqueio de firewall
    - **Validates: Requirements 6.4**

- [x] 5. Persistência e integração da Camada 4
  - [x] 5.1 Implementar persistência do IncidentReport no Elasticsearch
    - Adicionar método `persistir(report: IncidentReport)` ao `ReportGenerator` (ou `LLMAgent`)
    - Indexar no índice `incidents` com `incident_id` como document ID
    - Atualizar campo `agent_analyzed=True` no evento original em `threat-events-*`
    - _Requirements: 6.1, 15.4_

  - [ ]* 5.2 Escrever testes de integração da Camada 4
    - Testar fluxo completo: `ContextBuilder` → `LLMAgent` → `ReportGenerator` → ES (com ES real via Docker)
    - Verificar que `agent_analyzed=True` é atualizado no evento original
    - _Requirements: 3.1, 5.1, 6.1_

- [x] 6. Checkpoint — Camada 4 completa
  - Garantir que todos os testes em `tests/agent/` passam
  - Verificar que `LLMAgent.investigar()` nunca lança exceção para qualquer entrada válida
  - Perguntar ao usuário se há ajustes antes de prosseguir para a Camada 5.

- [x] 7. Estrutura base da Camada 5 — Resposta Automática
  - Criar `response/__init__.py` exportando as classes públicas da camada
  - Criar `tests/response/__init__.py` e `tests/response/conftest.py` com fixtures (mock subprocess, mock HTTP)
  - Definir o dataclass `ResponseAction` em `response/__init__.py` ou `response/models.py`
  - _Requirements: 15.5_

- [x] 8. Implementar FirewallManager
  - [x] 8.1 Criar `response/firewall.py` com a classe `FirewallManager`
    - Implementar `bloquear_ip(ip: str, duracao_segundos: int = 3600) -> ResponseAction`
    - Executar `iptables -I INPUT -s {ip} -j DROP` via `subprocess`
    - Verificar se IP já está bloqueado antes de adicionar regra (idempotência)
    - Persistir IP bloqueado em `/etc/threat-hunter/blocked_ips.conf`
    - Implementar `desbloquear_ip(ip: str) -> ResponseAction`
    - Implementar `listar_bloqueados() -> list[str]`
    - Retornar `ResponseAction(status="failed")` em caso de falha de permissão (nunca lançar exceção)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ]* 8.2 Escrever testes unitários para FirewallManager
    - Testar `bloquear_ip()` com mock de subprocess (sucesso)
    - Testar idempotência: segunda chamada com mesmo IP retorna `status="success"`
    - Testar `desbloquear_ip()` remove a regra
    - Testar `listar_bloqueados()` reflete estado atual
    - Testar falha de permissão retorna `status="failed"` sem exceção
    - _Requirements: 7.1–7.6_

  - [ ]* 8.3 Escrever property test — bloquear_ip é idempotente
    - **Property 14: FirewallManager.bloquear_ip() é idempotente**
    - Para qualquer IPv4 válido, duas chamadas consecutivas a `bloquear_ip()` retornam `status="success"` sem criar regras duplicadas
    - **Validates: Requirements 7.2**

  - [ ]* 8.4 Escrever property test — FirewallManager persiste IPs bloqueados
    - **Property 15: FirewallManager persiste IPs bloqueados**
    - Para qualquer IPv4 válido, após `bloquear_ip()` bem-sucedido, o IP aparece em `listar_bloqueados()`
    - **Validates: Requirements 7.3, 7.5**

  - [ ]* 8.5 Escrever property test — block/unblock é round-trip
    - **Property 16: FirewallManager block/unblock é round-trip**
    - Para qualquer IPv4 válido, após `bloquear_ip()` seguido de `desbloquear_ip()`, o IP não aparece em `listar_bloqueados()`
    - **Validates: Requirements 7.4**

  - [ ]* 8.6 Escrever property test — FirewallManager resiliente a falhas de permissão
    - **Property 17: FirewallManager é resiliente a falhas de permissão**
    - Para qualquer IPv4 válido com subprocess falhando por permissão, `bloquear_ip()` retorna `status="failed"` sem lançar exceção
    - **Validates: Requirements 7.6**

- [ ] 9. Implementar IsolationManager
  - [ ] 9.1 Criar `response/isolation.py` com a classe `IsolationManager`
    - Implementar `isolar_host(hostname: str) -> ResponseAction`
    - Adicionar regras iptables para dropar todo tráfego do host exceto porta 22 do bastion
    - Salvar estado de rede anterior do host para permitir reversão
    - Implementar `desfazer_isolamento(hostname: str) -> ResponseAction`
    - Restaurar estado de rede exatamente como estava antes do isolamento
    - Retornar `ResponseAction(status="failed")` em caso de falha (nunca lançar exceção)
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [ ]* 9.2 Escrever testes unitários para IsolationManager
    - Testar `isolar_host()` com mock de subprocess
    - Testar `desfazer_isolamento()` restaura estado anterior
    - Testar falha retorna `status="failed"` sem exceção
    - _Requirements: 8.1–8.4_

  - [ ]* 9.3 Escrever property test — isolamento é reversível
    - **Property 18: IsolationManager isolamento é reversível (round-trip)**
    - Para qualquer hostname válido, após `isolar_host()` seguido de `desfazer_isolamento()`, o host tem a mesma conectividade que antes
    - **Validates: Requirements 8.2, 8.4**

  - [ ]* 9.4 Escrever property test — IsolationManager resiliente a falhas
    - **Property 19: IsolationManager é resiliente a falhas**
    - Para qualquer hostname, se `isolar_host()` falhar, retorna `status="failed"` sem lançar exceção
    - **Validates: Requirements 8.3**

- [ ] 10. Implementar NotificationDispatcher
  - [ ] 10.1 Criar `response/notifications.py` com a classe `NotificationDispatcher`
    - Implementar `enviar_slack(report: IncidentReport, webhook_url: str) -> ResponseAction`
    - Implementar `enviar_telegram(report: IncidentReport, bot_token: str, chat_id: str) -> ResponseAction`
    - Implementar `enviar_email(report: IncidentReport, destinatarios: list[str]) -> ResponseAction`
    - Incluir `incident_id`, `severidade`, `resumo`, e `acoes_recomendadas` no conteúdo de cada notificação
    - Retornar `ResponseAction(status="failed")` se canal indisponível (nunca lançar exceção)
    - Completar envio em < 5s (timeout nas chamadas HTTP)
    - Ler tokens/webhooks exclusivamente de variáveis de ambiente
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 14.1_

  - [ ]* 10.2 Escrever testes unitários para NotificationDispatcher
    - Testar cada canal com mock HTTP (sucesso e falha)
    - Verificar que conteúdo inclui os 4 campos obrigatórios
    - Testar canal indisponível retorna `status="failed"` sem exceção
    - _Requirements: 9.1–9.5_

  - [ ]* 10.3 Escrever property test — NotificationDispatcher resiliente a canais indisponíveis
    - **Property 20: NotificationDispatcher é resiliente a canais indisponíveis**
    - Para qualquer IncidentReport com canal indisponível, o método de envio retorna `status="failed"` sem lançar exceção
    - **Validates: Requirements 9.4**

  - [ ]* 10.4 Escrever property test — NotificationDispatcher inclui campos obrigatórios
    - **Property 21: NotificationDispatcher inclui campos obrigatórios no conteúdo**
    - Para qualquer IncidentReport, o conteúdo da notificação inclui `incident_id`, `severidade`, `resumo`, e `acoes_recomendadas`
    - **Validates: Requirements 9.5**

- [ ] 11. Implementar ResponseOrchestrator e integração Camada 4 → 5
  - [ ] 11.1 Criar `response/orchestrator.py` com a classe `ResponseOrchestrator`
    - Implementar `executar(report: IncidentReport) -> list[ResponseAction]`
    - Para `score >= 80`: executar `bloquear_ip` + notificações + criar ticket
    - Para `score >= 60` e `< 80`: executar notificações + criar ticket (sem bloqueio)
    - Garantir que falha em uma ação não impede execução das demais (try/except por ação)
    - Registrar todas as ações tentadas na lista retornada (sucesso ou falha)
    - Completar em < 30s
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [ ] 11.2 Criar `response/ticket.py` com a classe `TicketCreator`
    - Implementar `criar(report: IncidentReport) -> ResponseAction`
    - Persistir ticket localmente (arquivo JSON em `response/tickets/`) como implementação mínima
    - Retornar `ResponseAction(status="failed")` em caso de falha (nunca lançar exceção)
    - _Requirements: 10.1, 10.2_

  - [ ]* 11.3 Escrever testes unitários para ResponseOrchestrator
    - Testar `score >= 80` executa as 3 ações (firewall + notificação + ticket)
    - Testar `score >= 60` e `< 80` executa apenas notificação + ticket
    - Testar que todas as ações com falha são registradas e execução continua
    - Testar retorno é sempre `list[ResponseAction]` mesmo com todas as ações falhando
    - _Requirements: 10.1–10.5_

  - [ ]* 11.4 Escrever property test — ResponseOrchestrator registra todas as ações
    - **Property 22: ResponseOrchestrator registra todas as ações tentadas**
    - Para qualquer IncidentReport com `score >= 60`, `executar()` retorna lista com uma entrada por ação tentada, independente de sucesso ou falha
    - **Validates: Requirements 10.3**

  - [ ]* 11.5 Escrever property test — ResponseOrchestrator continua após falhas
    - **Property 23: ResponseOrchestrator continua após falhas individuais**
    - Para qualquer IncidentReport onde todas as ações falham, `executar()` retorna lista com todas as ações como `status="failed"` sem lançar exceção
    - **Validates: Requirements 10.4**

- [ ] 12. Checkpoint — Camada 5 completa
  - Garantir que todos os testes em `tests/response/` passam
  - Verificar que `ResponseOrchestrator.executar()` nunca lança exceção para qualquer entrada válida
  - Perguntar ao usuário se há ajustes antes de prosseguir para a Camada 6.

- [ ] 13. Backend FastAPI — Estrutura e endpoints REST
  - [ ] 13.1 Criar estrutura de arquivos do backend
    - Criar `dashboard/backend/main.py` com app FastAPI e configuração de CORS
    - Criar `dashboard/backend/routes/__init__.py`
    - Criar `dashboard/backend/routes/incidents.py`
    - Criar `dashboard/backend/routes/health.py`
    - Criar `dashboard/backend/requirements.txt` com `fastapi`, `uvicorn`, `httpx`, `elasticsearch-py`, `python-jose`
    - _Requirements: 11.1, 14.2_

  - [ ] 13.2 Implementar `GET /incidents` e `GET /incidents/{incident_id}`
    - Implementar `GET /incidents?limit=50&severity=CRITICO&from=2026-01-01` com paginação
    - Retornar `{ total: int, incidents: [...] }` em < 500ms
    - Implementar `GET /incidents/{incident_id}` retornando IncidentReport completo + ResponseActions
    - Retornar HTTP 404 com mensagem descritiva para `incident_id` inexistente
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 13.3 Implementar `POST /incidents/{incident_id}/status` e `GET /health`
    - Implementar `POST /incidents/{incident_id}/status` aceitando `{ status: "resolved" | "false_positive" }`
    - Atualizar status no Elasticsearch e retornar HTTP 200
    - Implementar `GET /health` verificando estado real de `elasticsearch`, `logstash`, `ml_pipeline`, `llm_agent`
    - Retornar `score_saude` como float calculado a partir dos componentes ativos
    - _Requirements: 11.5, 11.6_

  - [ ] 13.4 Implementar autenticação JWT nos endpoints REST
    - Adicionar middleware de autenticação JWT para todos os endpoints REST
    - Implementar `POST /auth/token` para geração de token (usuário/senha via env vars)
    - Retornar HTTP 401 para requisições sem token válido
    - _Requirements: 14.2_

  - [ ]* 13.5 Escrever testes de API para endpoints REST
    - Testar `GET /incidents` com filtros (severity, limit, from)
    - Testar `GET /incidents/{id}` com ID válido e inválido (404)
    - Testar `POST /incidents/{id}/status` com status válido
    - Testar `GET /health` reflete estado real dos serviços
    - Testar autenticação JWT (401 sem token, 200 com token válido)
    - _Requirements: 11.1–11.6, 14.2_

  - [ ]* 13.6 Escrever property test — DashboardAPI filtra incidentes corretamente
    - **Property 24: DashboardAPI filtra incidentes corretamente**
    - Para qualquer combinação de parâmetros de filtro (`severity`, `limit`, `from`), todos os incidentes retornados satisfazem os critérios especificados
    - **Validates: Requirements 11.2**

- [ ] 14. Backend FastAPI — WebSocket para eventos em tempo real
  - [ ] 14.1 Criar `dashboard/backend/websocket.py` com gerenciador de conexões WebSocket
    - Implementar `ConnectionManager` com `connect()`, `disconnect()`, e `broadcast()`
    - Implementar endpoint `WebSocket /ws/events` com autenticação JWT via query param
    - Remover cliente da lista de conexões ativas ao desconectar (sem afetar outros clientes)
    - _Requirements: 12.1, 12.3, 12.4, 14.2_

  - [ ] 14.2 Integrar WebSocket com geração de IncidentReport
    - Emitir IncidentReport via WebSocket em < 1s após geração (para `score >= 60`)
    - Conectar `LLMAgent` ao `ConnectionManager` para broadcast automático
    - _Requirements: 12.2_

  - [ ]* 14.3 Escrever testes para WebSocket
    - Testar conexão e desconexão de clientes
    - Testar broadcast de IncidentReport para todos os clientes conectados
    - Testar que desconexão de um cliente não afeta os demais
    - _Requirements: 12.1–12.4_

- [ ] 15. Frontend React — Componentes e integração com API
  - [ ] 15.1 Criar estrutura do projeto React com TypeScript
    - Criar `dashboard/frontend/package.json` com dependências: `react`, `typescript`, `vite`, `axios`, `recharts`
    - Criar `dashboard/frontend/src/App.tsx` com roteamento básico
    - Criar tipos TypeScript espelhando `IncidentReport`, `ResponseAction`, e `SystemHealth`
    - _Requirements: 13.1_

  - [ ] 15.2 Implementar componente `IncidentList`
    - Criar `dashboard/frontend/src/components/IncidentList.tsx`
    - Buscar incidentes de `GET /incidents` ao carregar
    - Adicionar novos incidentes recebidos via WebSocket sem refresh manual
    - _Requirements: 13.1, 13.2_

  - [ ] 15.3 Implementar componente `IncidentDetail`
    - Criar `dashboard/frontend/src/components/IncidentDetail.tsx`
    - Exibir `linha_do_tempo`, `tecnicas_mitre`, e `acoes_recomendadas` ao selecionar incidente
    - Implementar botões "Resolver" e "Falso Positivo" que chamam `POST /incidents/{id}/status`
    - Atualizar status exibido sem reload completo da página
    - _Requirements: 13.3, 13.5_

  - [ ] 15.4 Implementar componente `SystemHealth`
    - Criar `dashboard/frontend/src/components/SystemHealth.tsx`
    - Buscar status de `GET /health` ao carregar o dashboard
    - Exibir status de cada componente (`elasticsearch`, `logstash`, `ml_pipeline`, `llm_agent`) como indicador visual
    - _Requirements: 13.4_

- [ ] 16. Checkpoint final — Integração completa e testes end-to-end
  - Garantir que todos os testes em `tests/agent/`, `tests/response/`, e `tests/dashboard/` passam
  - Verificar que o fluxo completo funciona: evento ML → LLMAgent → ResponseOrchestrator → WebSocket → UI
  - Perguntar ao usuário se há ajustes finais antes de encerrar.

## Notes

- Tarefas marcadas com `*` são opcionais e podem ser puladas para um MVP mais rápido
- Cada tarefa referencia requisitos específicos para rastreabilidade
- Os checkpoints nas tarefas 6, 12 e 16 garantem validação incremental entre camadas
- Property tests usam a biblioteca `hypothesis` (já listada nas dependências do design)
- O backend FastAPI deve ser iniciado manualmente com `uvicorn dashboard.backend.main:app --reload`
- O frontend React deve ser iniciado manualmente com `npm run dev` dentro de `dashboard/frontend/`
