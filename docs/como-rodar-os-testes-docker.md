# Como Rodar os Testes via Docker

Todos os testes rodam dentro de um container Docker isolado.
Você não precisa instalar Python, pytest ou qualquer dependência no seu computador.

**Pré-requisito:** Docker instalado e rodando.

---

## Primeira vez (build da imagem)

Na raiz do projeto, execute:

```bash
docker build -f docker/Dockerfile.test -t threat-hunter-tests .
```

Esse comando baixa as dependências e monta a imagem de testes.
Demora alguns minutos na primeira vez. Nas próximas execuções usa cache e é quase instantâneo.

---

## Rodando os testes

```bash
docker run --rm threat-hunter-tests
```

---

## Saída esperada (tudo certo)

```
============================= test session info ==============================
platform linux -- Python 3.12.13, pytest-8.2.0
rootdir: /app
plugins: cov-5.0.0
collected 74 items

tests/collector/test_log_collector.py::TestNormalizacaoAuthFailure::test_detecta_falha_ssh_por_senha PASSED [  1%]
tests/collector/test_log_collector.py::TestNormalizacaoAuthFailure::test_detecta_falha_ssh_usuario_invalido PASSED [  2%]
tests/collector/test_log_collector.py::TestNormalizacaoAuthSuccess::test_detecta_login_bem_sucedido PASSED [  6%]
tests/collector/test_log_collector.py::TestSchemaPadrao::test_campos_obrigatorios_presentes PASSED [ 12%]
tests/collector/test_log_collector.py::TestLinhasNaoReconhecidas::test_linha_irrelevante_retorna_none PASSED [ 21%]
tests/ml/test_preprocessor.py::TestExtrairFeatures::test_extrai_features_de_auth_failure PASSED [ 41%]
tests/ml/test_preprocessor.py::TestFitTransform::test_shape_de_saida_correto PASSED [ 51%]
tests/ml/test_anomaly_detector.py::TestTreinamento::test_fit_retorna_self PASSED [ 28%]
tests/ml/test_anomaly_detector.py::TestDeteccao::test_score_anomalia_dentro_do_intervalo PASSED [ 33%]
tests/ml/test_threat_classifier.py::TestPredicao::test_probabilidades_somam_um PASSED [ 87%]
tests/ml/test_scorer.py::TestCalcularScore::test_score_dentro_do_intervalo PASSED [ 59%]
tests/ml/test_scorer.py::TestThresholds::test_classificar_severidade[85.0-CRITICO] PASSED [ 64%]
... (todos os 74 testes aparecem com PASSED)

---------- coverage report ----------
Name                                  Stmts   Miss  Cover
---------------------------------------------------------
collector/syslog/log_collector.py        76     42    45%
ml/anomaly_detection/detector.py         45      0   100%
ml/preprocessor.py                       64      2    97%
ml/scorer.py                             65      0   100%
ml/threat_classifier/classifier.py       54      4    93%
---------------------------------------------------------
TOTAL                                   393    137    65%

============================== 74 passed in 20.03s ==============================
```

### O que confirma que está tudo certo

| Sinal | O que significa |
|---|---|
| `74 passed` | Todos os testes rodaram e passaram |
| `0 failed` | Nenhuma falha |
| `in ~20s` | Tempo normal de execução (pode variar) |
| `Exit Code: 0` | Sucesso — padrão Unix para "tudo ok" |

### Cobertura de código

O relatório de cobertura mostra quantas linhas de cada módulo foram exercitadas pelos testes:

| Cobertura | Interpretação |
|---|---|
| 100% | Todo o código foi testado |
| 90-99% | Excelente |
| 80-89% | Bom — padrão da indústria |
| Abaixo de 80% | Atenção — partes do código sem cobertura |

---

## Saída quando algo está errado

Se um teste falhar, você verá `FAILED` ao lado do nome e um resumo no final:

```
tests/ml/test_anomaly_detector.py::TestDeteccao::test_score_anomalia_dentro_do_intervalo FAILED [ 33%]

================================= FAILURES ==================================
_______ TestDeteccao.test_score_anomalia_dentro_do_intervalo ________

    def test_score_anomalia_dentro_do_intervalo(...):
>       assert scores.min() >= 0.0
E       AssertionError: assert -0.3 >= 0.0

========================= 1 failed, 73 passed in 21.5s ==========================
```

O pytest mostra exatamente qual linha falhou e qual valor foi obtido versus o esperado.

---

## Rodando apenas um módulo específico

```bash
# Apenas testes do collector
docker run --rm threat-hunter-tests pytest tests/collector/ -v

# Apenas testes do ML
docker run --rm threat-hunter-tests pytest tests/ml/ -v

# Apenas um arquivo
docker run --rm threat-hunter-tests pytest tests/ml/test_scorer.py -v
```

---

## Quando rebuildar a imagem

Você precisa rebuildar apenas quando:
- Adicionar novas dependências ao `requirements.txt`
- Modificar o `Dockerfile.test`

Para qualquer outra mudança no código ou nos testes, o `docker run` já pega a versão mais recente automaticamente porque o código é copiado no build.

```bash
# Rebuild forçado (sem cache)
docker build --no-cache -f docker/Dockerfile.test -t threat-hunter-tests .
```
