"""
Camada 4 — Agente LLM — AI-Powered Threat Hunter
=================================================
Responsabilidade:
    Receber alertas com score >= 60 provenientes do pipeline de ML,
    enriquecer com contexto histórico do Elasticsearch, mapear técnicas
    no framework MITRE ATT&CK e gerar relatório narrativo de incidente.

Componentes:
    ContextBuilder   — Busca e agrega contexto histórico no Elasticsearch.
    MITREMapper      — Mapeia classes de ameaça para técnicas ATT&CK.
    LLMAgent         — Orquestra a investigação via Claude / GPT-4.
    ReportGenerator  — Produz o IncidentReport estruturado final.

Classes exportadas (disponíveis após implementação das tasks seguintes):
    ThreatContext    — Contexto enriquecido enviado ao LLM.
    IncidentReport   — Relatório de incidente gerado pelo agente.
    ContextBuilder
    MITREMapper
    LLMAgent
    ReportGenerator
"""

# As classes serão exportadas aqui à medida que forem implementadas
# nas tasks subsequentes (2, 3 e 4).
