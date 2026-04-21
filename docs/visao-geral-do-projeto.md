# Visão Geral do Projeto — AI-Powered Threat Hunter

## Antes de tudo: o problema real

Imagine que você é dono de uma empresa. Você tem servidores, computadores, sistemas rodando. E você contratou um segurança para ficar de plantão na porta.

Só que esse segurança tem um problema: ele recebe **centenas de alertas por hora**. Toda vez que alguém tenta abrir uma porta, ele recebe um aviso. Toda vez que alguém digita a senha errada, ele recebe um aviso. Toda vez que um sistema faz algo incomum, ele recebe um aviso.

Com o tempo, ele começa a ignorar os alertas. Não porque é negligente — mas porque é humanamente impossível analisar tudo. E é exatamente nessa brecha que os atacantes entram.

**O AI-Powered Threat Hunter existe para resolver isso.**

---

## O que o projeto faz, em uma frase

É um sistema que fica de olho na sua rede e nos seus servidores **24 horas por dia, 7 dias por semana**, detecta comportamentos suspeitos, entende o que está acontecendo e toma as primeiras ações de defesa — tudo isso de forma automática, sem precisar de um humano para cada decisão.

---

## Uma analogia para entender tudo

Pense no projeto como um **hospital com vários especialistas trabalhando juntos**:

- A **recepção** (Coleta de Dados) recebe todos os pacientes — ou seja, todos os eventos que acontecem na rede.
- A **triagem** (Normalização) organiza as informações de cada paciente num formato padrão para que os médicos possam entender.
- O **clínico geral** (Machine Learning) examina cada paciente e diz: "esse aqui está com febre alta, esse está normal, esse tem sintomas de algo grave".
- O **especialista** (Agente de IA) pega os casos graves, investiga a fundo, descobre o que está acontecendo e escreve um laudo completo.
- A **equipe de emergência** (Resposta Automática) age imediatamente nos casos críticos — sem esperar o médico chefe chegar.
- O **painel de controle** (Dashboard) mostra o estado de saúde geral de tudo em tempo real para quem está supervisionando.

---

## Como o sistema funciona, passo a passo

### Passo 1 — O sistema fica de olho em tudo

O projeto monitora três fontes de informação ao mesmo tempo:

**Tráfego de rede**
Tudo que entra e sai dos servidores é observado. Se alguém de fora tenta se conectar 800 vezes em 2 minutos, o sistema vê isso. Se um computador interno começa a enviar uma quantidade absurda de dados para fora, o sistema vê isso também.

**Logs do sistema operacional**
Cada servidor guarda um diário de tudo que acontece: quem fez login, quem tentou e falhou, quais comandos foram executados, quais arquivos foram acessados. O sistema lê esse diário em tempo real.

**Logs de aplicação**
Os sistemas web e APIs também geram registros. Se alguém tenta invadir um sistema digitando comandos maliciosos no campo de login, isso aparece aqui.

---

### Passo 2 — Tudo é organizado num formato padrão

O problema é que cada fonte de informação fala uma língua diferente. O log do servidor tem um formato, o tráfego de rede tem outro, a aplicação web tem outro.

O Logstash (uma ferramenta de processamento de dados) pega tudo isso e traduz para um formato único, como se fosse um intérprete universal. Depois disso, cada evento fica assim:

```
Quando aconteceu: 19/04/2026 às 14:32
O que aconteceu:  Falha de autenticação
De onde veio:     IP 203.0.113.5
Quantas vezes:    847 tentativas
Gravidade:        (ainda não calculada)
```

---

### Passo 3 — A inteligência artificial analisa cada evento

Aqui entram dois modelos de Machine Learning trabalhando juntos. Pense neles como dois detetives com habilidades diferentes:

**Detetive 1 — O que conhece o "normal"**
Esse detetive passou semanas observando o comportamento da rede. Ele sabe que normalmente um usuário faz login uma vez por dia, que o servidor recebe em média 500 conexões por hora, que os arquivos são acessados num ritmo previsível.

Quando algo foge desse padrão — mesmo que seja algo nunca visto antes — ele levanta a mão e diz: "isso aqui está estranho".

Esse é o **Isolation Forest**, um algoritmo que detecta anomalias sem precisar ter visto o ataque antes.

**Detetive 2 — O que conhece os criminosos**
Esse detetive estudou milhares de ataques reais documentados. Ele sabe exatamente como um ataque de força bruta se parece, como uma varredura de portas se comporta, como um invasor se move lateralmente dentro de uma rede.

Quando ele vê um evento, ele classifica: "isso é Brute Force", "isso é DDoS", "isso é tentativa de escalonamento de privilégio".

Esse é o **Random Forest**, treinado com datasets reais de ataques.

Juntos, eles geram um **score de risco de 0 a 100** para cada evento:
- 0 a 20 → Normal, apenas registra
- 20 a 40 → Baixo, fica de olho
- 40 a 60 → Médio, alerta para revisão
- 60 a 80 → Alto, aciona investigação automática
- 80 a 100 → Crítico, resposta imediata

---

### Passo 4 — O agente de IA investiga como um analista sênior

Quando o score passa de 60, entra em cena o diferencial do projeto: um **agente de inteligência artificial** (usando modelos como Claude ou GPT-4) que faz o que nenhuma ferramenta tradicional faz — ele **pensa**.

Ele não apenas vê o alerta. Ele investiga:

- "Esse IP já apareceu antes nos últimos 30 dias?"
- "O que mais aconteceu nesse servidor nos últimos 10 minutos?"
- "Esse usuário costuma fazer login às 3 da manhã?"
- "Esse comportamento se encaixa em algum padrão de ataque documentado?"

E no final, ele escreve um relatório completo em linguagem humana, como se fosse um analista de segurança explicando o que aconteceu:

```
INCIDENTE #2026-042 — SEVERIDADE: CRÍTICA

O que aconteceu:
  Um atacante externo tentou acessar o servidor web-01 usando
  força bruta SSH. Após 847 tentativas, conseguiu acesso com
  o usuário "deploy" e imediatamente tentou obter privilégios
  de administrador.

Linha do tempo:
  14:30 — 847 tentativas de login falhas do IP 203.0.113.5
  14:32 — Login bem-sucedido com usuário "deploy"
  14:33 — Tentativa de escalonamento de privilégio (sudo su)

O que pode ter sido comprometido:
  Acesso potencial de administrador ao servidor web-01

O que deve ser feito:
  1. Bloquear o IP 203.0.113.5 imediatamente
  2. Revogar a sessão do usuário "deploy"
  3. Verificar todos os comandos executados após 14:32

Tipo de ataque (MITRE ATT&CK):
  T1110 (Força Bruta) → T1078 (Uso de Credenciais Válidas)
```

---

### Passo 5 — O sistema age sozinho nos casos críticos

Para alertas com score acima de 80, o sistema não espera ninguém ler o relatório. Ele age imediatamente:

**Bloqueia o atacante**
Adiciona o IP malicioso nas regras do firewall do servidor. O atacante é cortado da rede em segundos.

**Isola o servidor comprometido**
Se um servidor foi invadido, ele é desconectado da rede interna para evitar que o invasor se mova para outros sistemas.

**Avisa as pessoas certas**
Envia uma notificação via Slack, Telegram ou e-mail para a equipe de segurança com o resumo do incidente.

**Abre um ticket**
Cria automaticamente um registro no sistema de gestão para que o time possa acompanhar e documentar a resposta.

Tudo isso acontece em **menos de 30 segundos** após a detecção.

---

### Passo 6 — O painel de controle mostra tudo

Um analista humano pode acompanhar tudo em tempo real através de um dashboard visual:

- Mapa de calor mostrando os horários com mais atividade suspeita
- Gráficos de ameaças por tipo e gravidade
- Linha do tempo de cada incidente
- Status de todas as ações automáticas executadas
- Nota de saúde geral da rede (como um termômetro de segurança)

---

## Como as peças se comunicam

Aqui está o caminho que um evento percorre desde que acontece até a resposta:

```
Um atacante tenta fazer login 847 vezes
            ↓
O coletor de logs detecta as tentativas no auth.log
            ↓
O Logstash normaliza e envia para o Elasticsearch
            ↓
O modelo de anomalias detecta: "isso é muito acima do normal"
O modelo de classificação identifica: "isso é Brute Force"
Score calculado: 87/100 — CRÍTICO
            ↓
O agente de IA investiga o contexto completo
e gera o relatório de incidente
            ↓
A resposta automática bloqueia o IP no firewall
e notifica a equipe via Slack
            ↓
O analista humano vê tudo no dashboard
e decide os próximos passos
```

Todo esse caminho acontece em menos de 1 minuto.

---

## O que torna esse projeto diferente

A maioria das ferramentas de segurança para no terceiro passo — elas detectam e geram um alerta. Ponto.

O analista humano precisa então abrir o alerta, investigar manualmente, correlacionar com outros eventos, entender o contexto, decidir o que fazer e agir. Isso leva tempo — às vezes horas.

Nesse projeto, **os passos 4 e 5 são automatizados**. O sistema não apenas detecta — ele entende, explica e age. O analista humano entra em cena já com o contexto completo e as primeiras ações já tomadas.

É a diferença entre receber um alarme de incêndio e receber um relatório dizendo: "incêndio no terceiro andar, sala 302, os sprinklers já foram acionados, aqui está o que você precisa fazer agora".

---

## Tecnologias utilizadas e por quê cada uma foi escolhida

| Tecnologia | Função | Por que foi escolhida |
|---|---|---|
| Zeek / Suricata | Captura tráfego de rede | Ferramentas open source usadas por empresas reais |
| Logstash | Normaliza e processa os logs | Parte do ELK Stack, padrão da indústria |
| Elasticsearch | Armazena e indexa os eventos | Busca ultrarrápida em grandes volumes de dados |
| Kibana | Dashboard visual | Interface nativa do Elasticsearch |
| Isolation Forest | Detecta anomalias | Funciona sem exemplos de ataques, detecta o desconhecido |
| Random Forest | Classifica ameaças | Robusto, interpretável e eficiente |
| Claude / GPT-4 | Agente investigativo | Capacidade de raciocínio contextual e linguagem natural |
| Docker | Infraestrutura | Garante que tudo roda igual em qualquer ambiente |
| Python | Linguagem principal | Ecossistema rico para ML e automação |

---

## O que o projeto NÃO faz

É importante ser honesto sobre os limites:

- **Não substitui completamente um analista humano.** Ele cuida da primeira linha de resposta. Decisões estratégicas, investigações forenses profundas e comunicação com clientes ainda precisam de pessoas.
- **Não é infalível.** Nenhum sistema de segurança é. Ele pode gerar falsos positivos (alertar sobre algo normal) ou falsos negativos (não detectar um ataque muito sofisticado).
- **Precisa de um período de aprendizado.** O modelo de anomalias precisa de 7 a 14 dias observando o comportamento normal da rede antes de começar a detectar desvios com precisão.

---

## Resumo em uma imagem mental

Se você precisasse explicar esse projeto para alguém em 30 segundos, diria assim:

> "É como ter um segurança robô que nunca dorme, que conhece todos os tipos de ataque que existem, que aprende como a sua rede se comporta normalmente, e que quando detecta algo errado não apenas grita 'tem um problema!' — ele investiga, escreve um relatório completo e já toma as primeiras ações de defesa, tudo em menos de um minuto."
