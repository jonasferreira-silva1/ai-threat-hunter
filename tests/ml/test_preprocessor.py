"""
Testes do Pré-processador — AI-Powered Threat Hunter
=====================================================
Cobre:
    - Extração de features de cada tipo de evento
    - Tratamento de campos ausentes (defaults seguros)
    - Treinamento e transformação
    - Consistência do shape de saída
    - Persistência (salvar/carregar)
"""

import pytest
import numpy as np
from ml.preprocessor import Preprocessor, NUMERIC_FEATURES, CATEGORICAL_FEATURES


# Número total de features esperado na saída
N_FEATURES_ESPERADO = len(NUMERIC_FEATURES) + len(CATEGORICAL_FEATURES)


class TestExtrairFeatures:
    """Testa a extração de features de eventos individuais."""

    @pytest.mark.unit
    def test_extrai_features_de_auth_failure(self, evento_auth_failure):
        preprocessor = Preprocessor()
        features = preprocessor.extrair_features(evento_auth_failure)

        assert features["count"] == 847.0
        assert features["event_type"] == "auth_failure"
        assert features["category"] == "authentication"

    @pytest.mark.unit
    def test_extrai_features_de_network_connection(self, evento_network_normal):
        preprocessor = Preprocessor()
        features = preprocessor.extrair_features(evento_network_normal)

        assert features["bytes_sent"] == 2048.0
        assert features["bytes_received"] == 8192.0
        assert features["protocol"] == "TCP"

    @pytest.mark.unit
    def test_campos_ausentes_recebem_defaults(self):
        """Evento mínimo sem campos opcionais não deve lançar exceção."""
        evento_minimo = {
            "timestamp": "2026-04-19T14:30:00Z",
            "event_type": "auth_failure",
        }
        preprocessor = Preprocessor()
        features = preprocessor.extrair_features(evento_minimo)

        # Campos ausentes devem ter valor padrão neutro
        assert features["count"] == 1.0
        assert features["bytes_sent"] == 0.0
        assert features["bytes_received"] == 0.0
        assert features["protocol"] == "unknown"
        assert features["category"] == "unknown"

    @pytest.mark.unit
    def test_extrai_hora_do_timestamp(self):
        """Hora do evento deve ser extraída corretamente do timestamp."""
        evento = {
            "timestamp": "2026-04-19T03:15:00+00:00",
            "event_type": "auth_failure",
        }
        preprocessor = Preprocessor()
        features = preprocessor.extrair_features(evento)

        assert features["hour"] == 3.0

    @pytest.mark.unit
    def test_timestamp_invalido_nao_lanca_excecao(self):
        """Timestamp malformado deve ser tratado com graciosidade."""
        evento = {"timestamp": "data-invalida", "event_type": "auth_failure"}
        preprocessor = Preprocessor()

        # Não deve lançar exceção
        features = preprocessor.extrair_features(evento)
        assert "hour" in features


class TestFitTransform:
    """Testa o treinamento e transformação do pré-processador."""

    @pytest.mark.unit
    def test_fit_retorna_self(self, lista_eventos_normais):
        preprocessor = Preprocessor()
        resultado = preprocessor.fit(lista_eventos_normais)

        assert resultado is preprocessor

    @pytest.mark.unit
    def test_transform_retorna_array_numpy(self, lista_eventos_normais):
        preprocessor = Preprocessor()
        preprocessor.fit(lista_eventos_normais)
        X = preprocessor.transform(lista_eventos_normais)

        assert isinstance(X, np.ndarray)

    @pytest.mark.unit
    def test_shape_de_saida_correto(self, lista_eventos_normais):
        """Shape deve ser (n_eventos, n_features)."""
        preprocessor = Preprocessor()
        X = preprocessor.fit_transform(lista_eventos_normais)

        assert X.shape == (len(lista_eventos_normais), N_FEATURES_ESPERADO)

    @pytest.mark.unit
    def test_transform_sem_fit_lanca_excecao(self, lista_eventos_normais):
        preprocessor = Preprocessor()

        with pytest.raises(RuntimeError, match="não treinado"):
            preprocessor.transform(lista_eventos_normais)

    @pytest.mark.unit
    def test_fit_transform_equivale_a_fit_mais_transform(self, lista_eventos_normais):
        """fit_transform deve produzir o mesmo resultado que fit() + transform()."""
        p1 = Preprocessor()
        X1 = p1.fit_transform(lista_eventos_normais)

        p2 = Preprocessor()
        p2.fit(lista_eventos_normais)
        X2 = p2.transform(lista_eventos_normais)

        np.testing.assert_array_almost_equal(X1, X2)

    @pytest.mark.unit
    def test_valores_desconhecidos_nao_lancam_excecao(self, lista_eventos_normais):
        """Evento com categoria nunca vista no treino não deve lançar exceção."""
        preprocessor = Preprocessor()
        preprocessor.fit(lista_eventos_normais)

        evento_desconhecido = [{
            "timestamp": "2026-04-19T14:30:00Z",
            "event_type": "tipo_nunca_visto",
            "count": 1,
            "bytes_sent": 0,
            "bytes_received": 0,
            "duration_ms": 0.0,
            "protocol": "protocolo_novo",
            "category": "categoria_nova",
            "http_status": 0,
        }]

        # Não deve lançar exceção
        X = preprocessor.transform(evento_desconhecido)
        assert X.shape == (1, N_FEATURES_ESPERADO)


class TestPersistencia:
    """Testa salvar e carregar o pré-processador."""

    @pytest.mark.unit
    def test_salvar_e_carregar_mantem_comportamento(self, lista_eventos_normais, tmp_path):
        caminho = tmp_path / "preprocessor_test.joblib"

        # Treina e salva
        p_original = Preprocessor()
        X_original = p_original.fit_transform(lista_eventos_normais)
        p_original.salvar(caminho)

        # Carrega e transforma
        p_carregado = Preprocessor.carregar(caminho)
        X_carregado = p_carregado.transform(lista_eventos_normais)

        np.testing.assert_array_almost_equal(X_original, X_carregado)
