# Como Rodar o Projeto

## Pré-requisitos

- Docker e Docker Compose instalados
- Python 3.11+
- 4 GB de RAM disponível para o ELK Stack

---

## 1. Subir a infraestrutura ELK

```bash
cd docker
docker-compose up -d
```

Aguarde ~60 segundos para o Elasticsearch inicializar completamente.

Verifique se os serviços estão saudáveis:

```bash
docker-compose ps
```

Acesse o Kibana: [http://localhost:5601](http://localhost:5601)
- Usuário: `elastic`
- Senha: valor de `ELASTIC_PASSWORD` no `.env` (padrão: `changeme123`)

---

## 2. Instalar dependências Python

```bash
# Coletor de logs
pip install -r collector/syslog/requirements.txt

# Módulo de ML
pip install -r ml/requirements.txt
```

---

## 3. Treinar os modelos de ML

```bash
# A partir da raiz do projeto
python -m ml.trainer
```

O trainer vai:
1. Tentar carregar eventos do Elasticsearch (se houver dados coletados)
2. Usar dados sintéticos como fallback se o Elasticsearch estiver vazio
3. Salvar os modelos treinados em `ml/artifacts/`

Para usar o dataset CICIDS2017 real, baixe em:
https://www.unb.ca/cic/datasets/ids-2017.html

Coloque o arquivo em `ml/datasets/CICIDS2017_sample.csv` antes de rodar o trainer.

---

## 4. Iniciar o coletor de logs

```bash
python -m collector.syslog.log_collector
```

O coletor monitora `/var/log/auth.log` e `/var/log/syslog` em tempo real.
Eventos detectados aparecem no Kibana em segundos.

---

## 5. Rodar os testes

```bash
# Todos os testes unitários
pytest -m unit

# Todos os testes
pytest

# Com cobertura de código
pytest --cov=ml --cov=collector --cov-report=term-missing
```

---

## Variáveis de Ambiente

Todas as configurações ficam no arquivo `.env` na raiz do projeto.
Copie o `.env` de exemplo e ajuste conforme necessário:

| Variável | Padrão | Descrição |
|---|---|---|
| `ELK_VERSION` | `8.13.0` | Versão do ELK Stack |
| `ELASTIC_PASSWORD` | `changeme123` | Senha do usuário `elastic` |
| `ELASTIC_PORT` | `9200` | Porta da API do Elasticsearch |
| `KIBANA_PORT` | `5601` | Porta do Kibana |
| `LOGSTASH_PORT_TCP` | `5044` | Porta TCP do Logstash |
| `COLLECTOR_HOST` | `localhost` | Host do Logstash para o coletor |
| `LOG_LEVEL` | `INFO` | Nível de log da aplicação |

---

## Parar os serviços

```bash
cd docker
docker-compose down

# Para remover também os volumes (apaga todos os dados)
docker-compose down -v
```
