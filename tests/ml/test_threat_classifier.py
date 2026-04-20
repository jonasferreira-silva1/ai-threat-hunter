"""
Testes do Classificador de Ameaças — AI-Powered Threat Hunter
=============================================================
Cobre:
    - Treinamento com dados rotulados
    - Predição de classes conhecidas
    - Probabilidades somam 1.0 por evento
    - Severidade base por classe
    - Comportamento sem treinamento
    - Persistência do modelo
"""

import pytest
import numpy as np
from ml.threat_classifier.classifier import (
    ThreatClassifier,
    CLASSES_AMEACA,
    SEVERIDADE_POR_CLASSE,
)
from ml.preprocessor import Preprocessor


@pytest.fixture
def dados_treinamento(lista_eventos_normais):
    """Features e labels sintéticos para treinar o classificador nos testes."""
    preprocessor = Preprocessor()
    X = preprocessor.fit_transform(lista_eventos_normais)

    # Labels sintéticos: maioria normal, alguns ataques
    np.random.seed(42)
    y = np.random.choice(
        list(CLASSES_AMEACA.keys()),
        size=len(lista_eventos_normais),
        p=[0.70, 0.10, 0.05, 0.05, 0.04, 0.03, 0.03],
    )
    return X, y, preprocessor


@pytest.fixture
def classifier_treinado(dados_treinamento):
    """Classificador já treinado — reutilizado entre testes."""
    X, y, preprocessor = dados_treinamento
    classifier = ThreatClassifier(n_estimators=10)  # Rápido para testes
    classifier.fit(X, y)
    return classifier, preprocessor


class TestTreinamento:
    """Testa o processo de treinamento do Random Forest."""

    @pytest.mark.unit
    def test_fit_retorna_self(self, dados_treinamento):
        X, y, _ = dados_treinamento
        classifier = ThreatClassifier(n_estimators=10)
        resultado = classifier.fit(X, y)

        assert resultado is classifier

    @pytest.mark.unit
    def test_is_fitted_apos_treinamento(self, dados_treinamento):
        X, y, _ = dados_treinamento
        classifier = ThreatClassifier(n_estimators=10)
        assert not classifier.is_fitted

        classifier.fit(X, y)
        assert classifier.is_fitted

    @pytest.mark.unit
    def test_predict_sem_fit_lanca_excecao(self, vetor_features_simples):
        classifier = ThreatClassifier()

        with pytest.raises(RuntimeError, match="não treinado"):
            classifier.predict(vetor_features_simples)


class TestPredicao:
    """Testa as predições do classificador."""

    @pytest.mark.unit
    def test_predict_retorna_lista_de_strings(self, classifier_treinado, lista_eventos_normais):
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)
        predicoes = classifier.predict(X)

        assert isinstance(predicoes, list)
        assert all(isinstance(p, str) for p in predicoes)

    @pytest.mark.unit
    def test_predict_retorna_apenas_classes_conhecidas(self, classifier_treinado, lista_eventos_normais):
        """Todas as predições devem ser classes definidas em CLASSES_AMEACA."""
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)
        predicoes = classifier.predict(X)

        classes_validas = set(CLASSES_AMEACA.values())
        for predicao in predicoes:
            assert predicao in classes_validas, f"Classe inválida retornada: '{predicao}'"

    @pytest.mark.unit
    def test_predict_quantidade_igual_a_entrada(self, classifier_treinado, lista_eventos_normais):
        """Deve retornar uma predição por evento de entrada."""
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)
        predicoes = classifier.predict(X)

        assert len(predicoes) == len(lista_eventos_normais)

    @pytest.mark.unit
    def test_predict_proba_retorna_lista_de_dicts(self, classifier_treinado, lista_eventos_normais):
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)
        probabilidades = classifier.predict_proba(X)

        assert isinstance(probabilidades, list)
        assert all(isinstance(p, dict) for p in probabilidades)

    @pytest.mark.unit
    def test_probabilidades_somam_um(self, classifier_treinado, lista_eventos_normais):
        """A soma das probabilidades de todas as classes deve ser ~1.0."""
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)
        probabilidades = classifier.predict_proba(X)

        for probs in probabilidades:
            soma = sum(probs.values())
            assert abs(soma - 1.0) < 1e-4, f"Probabilidades somam {soma}, esperado ~1.0"

    @pytest.mark.unit
    def test_probabilidades_contem_todas_as_classes(self, classifier_treinado, vetor_features_simples):
        """Cada predição deve conter probabilidade para todas as classes."""
        classifier, _ = classifier_treinado
        probabilidades = classifier.predict_proba(vetor_features_simples)

        classes_esperadas = set(CLASSES_AMEACA.values())
        classes_retornadas = set(probabilidades[0].keys())

        assert classes_esperadas == classes_retornadas


class TestSeveridade:
    """Testa o mapeamento de severidade por classe."""

    @pytest.mark.unit
    @pytest.mark.parametrize("classe,severidade_minima", [
        ("NORMAL",               0),
        ("BRUTE_FORCE",         60),
        ("DDOS",                70),
        ("LATERAL_MOVEMENT",    80),
        ("DATA_EXFILTRATION",   85),
        ("PRIVILEGE_ESCALATION", 80),
    ])
    def test_severidade_base_por_classe(self, classe, severidade_minima):
        """Classes de ataque devem ter severidade acima do mínimo esperado."""
        classifier = ThreatClassifier()
        severidade = classifier.severidade_base(classe)

        assert severidade >= severidade_minima, (
            f"Classe '{classe}': severidade {severidade} abaixo do mínimo {severidade_minima}"
        )

    @pytest.mark.unit
    def test_classe_desconhecida_retorna_severidade_padrao(self):
        """Classe não mapeada deve retornar severidade padrão (50), não lançar exceção."""
        classifier = ThreatClassifier()
        severidade = classifier.severidade_base("CLASSE_INEXISTENTE")

        assert severidade == 50


class TestPersistencia:
    """Testa salvar e carregar o classificador."""

    @pytest.mark.unit
    def test_salvar_e_carregar_mantem_predicoes(self, classifier_treinado, lista_eventos_normais, tmp_path):
        classifier, preprocessor = classifier_treinado
        X = preprocessor.transform(lista_eventos_normais)

        caminho = tmp_path / "classifier_test.joblib"
        classifier.salvar(caminho)

        classifier_carregado = ThreatClassifier.carregar(caminho)
        predicoes_originais = classifier.predict(X)
        predicoes_carregadas = classifier_carregado.predict(X)

        assert predicoes_originais == predicoes_carregadas
