"""
Testes do Detector de Anomalias — AI-Powered Threat Hunter
===========================================================
Cobre:
    - Treinamento com dados normais
    - Detecção de eventos claramente anômalos
    - Score de anomalia dentro do intervalo esperado [0, 1]
    - Comportamento sem treinamento prévio
    - Persistência do modelo
"""

import pytest
import numpy as np
from ml.anomaly_detection.detector import AnomalyDetector
from ml.preprocessor import Preprocessor


@pytest.fixture
def detector_treinado(lista_eventos_normais):
    """Detector já treinado com eventos normais — reutilizado entre testes."""
    preprocessor = Preprocessor()
    X = preprocessor.fit_transform(lista_eventos_normais)

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(X)
    return detector, preprocessor


class TestTreinamento:
    """Testa o processo de treinamento do Isolation Forest."""

    @pytest.mark.unit
    def test_fit_retorna_self(self, lista_eventos_normais):
        preprocessor = Preprocessor()
        X = preprocessor.fit_transform(lista_eventos_normais)

        detector = AnomalyDetector()
        resultado = detector.fit(X)

        assert resultado is detector

    @pytest.mark.unit
    def test_is_fitted_apos_treinamento(self, lista_eventos_normais):
        preprocessor = Preprocessor()
        X = preprocessor.fit_transform(lista_eventos_normais)

        detector = AnomalyDetector()
        assert not detector.is_fitted

        detector.fit(X)
        assert detector.is_fitted

    @pytest.mark.unit
    def test_predict_sem_fit_lanca_excecao(self, vetor_features_simples):
        detector = AnomalyDetector()

        with pytest.raises(RuntimeError, match="não treinado"):
            detector.predict(vetor_features_simples)

    @pytest.mark.unit
    def test_score_sem_fit_lanca_excecao(self, vetor_features_simples):
        detector = AnomalyDetector()

        with pytest.raises(RuntimeError, match="não treinado"):
            detector.score_anomalia(vetor_features_simples)


class TestDeteccao:
    """Testa a capacidade de detecção de anomalias."""

    @pytest.mark.unit
    def test_score_anomalia_dentro_do_intervalo(self, detector_treinado, lista_eventos_normais):
        """Scores devem estar sempre entre 0.0 e 1.0."""
        detector, preprocessor = detector_treinado
        X = preprocessor.transform(lista_eventos_normais)
        scores = detector.score_anomalia(X)

        assert scores.min() >= 0.0
        assert scores.max() <= 1.0

    @pytest.mark.unit
    def test_predict_retorna_apenas_1_ou_menos_1(self, detector_treinado, lista_eventos_normais):
        """predict() deve retornar apenas 1 (normal) ou -1 (anômalo)."""
        detector, preprocessor = detector_treinado
        X = preprocessor.transform(lista_eventos_normais)
        predicoes = detector.predict(X)

        valores_unicos = set(predicoes)
        assert valores_unicos.issubset({1, -1})

    @pytest.mark.unit
    def test_evento_extremamente_anomalo_tem_score_alto(self, detector_treinado):
        """
        Evento com valores extremos deve ter score de anomalia alto.
        Cria um vetor com valores muito distantes do padrão normal.
        """
        detector, _ = detector_treinado

        # Vetor com valores extremos — muito diferente do baseline normal
        X_anomalo = np.array([[99999.0, 99999.0, 99999.0, 99999.0, 3.0, 6.0, 500.0, 0.0, 0.0, 0.0]])
        score = detector.score_anomalia(X_anomalo)[0]

        # Score deve ser alto (acima de 0.5) para evento claramente anômalo
        assert score > 0.5, f"Score esperado > 0.5, obtido: {score}"

    @pytest.mark.unit
    def test_is_anomalo_com_threshold_customizado(self, detector_treinado, lista_eventos_normais):
        """is_anomalo() deve respeitar o threshold informado."""
        detector, preprocessor = detector_treinado
        X = preprocessor.transform(lista_eventos_normais)

        # Com threshold 0.0, todos os eventos são anômalos
        todos_anomalos = detector.is_anomalo(X, threshold=0.0)
        assert todos_anomalos.all()

        # Com threshold 1.0, nenhum evento é anômalo (score nunca chega a 1.0 exato)
        nenhum_anomalo = detector.is_anomalo(X, threshold=1.0)
        assert not nenhum_anomalo.any()

    @pytest.mark.unit
    def test_shape_de_saida_do_score(self, detector_treinado, lista_eventos_normais):
        """Score deve ter uma entrada por evento."""
        detector, preprocessor = detector_treinado
        X = preprocessor.transform(lista_eventos_normais)
        scores = detector.score_anomalia(X)

        assert scores.shape == (len(lista_eventos_normais),)


class TestPersistencia:
    """Testa salvar e carregar o detector."""

    @pytest.mark.unit
    def test_salvar_e_carregar_mantem_predicoes(self, detector_treinado, lista_eventos_normais, tmp_path):
        detector, preprocessor = detector_treinado
        X = preprocessor.transform(lista_eventos_normais)

        caminho = tmp_path / "detector_test.joblib"
        detector.salvar(caminho)

        detector_carregado = AnomalyDetector.carregar(caminho)
        scores_carregados = detector_carregado.score_anomalia(X)
        scores_originais = detector.score_anomalia(X)

        np.testing.assert_array_almost_equal(scores_originais, scores_carregados)
