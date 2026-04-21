"""
Testes do Script de Treinamento — AI-Powered Threat Hunter
===========================================================
Cobre:
    - gerar_dados_sinteticos(): estrutura e tipos dos dados gerados
    - treinar_detector_anomalias(): pipeline completo de treinamento
    - treinar_classificador(): fallback para dados sintéticos
    - carregar_dataset_cicids(): parsing e mapeamento de labels
    - carregar_eventos_elasticsearch(): comportamento com mock do ES
    - main(): orquestração completa com fallback

Todas as dependências externas (Elasticsearch, filesystem)
são substituídas por mocks.
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import MagicMock, patch

from ml.trainer import (
    gerar_dados_sinteticos,
    treinar_detector_anomalias,
    treinar_classificador,
    carregar_dataset_cicids,
    carregar_eventos_elasticsearch,
    main,
)
from ml.preprocessor import Preprocessor
from ml.anomaly_detection.detector import AnomalyDetector
from ml.threat_classifier.classifier import ThreatClassifier


# =============================================================
# Testes de gerar_dados_sinteticos()
# =============================================================

class TestGerarDadosSinteticos:
    """Testa a geração de dados sintéticos para treinamento."""

    @pytest.mark.unit
    def test_retorna_quantidade_correta(self):
        eventos = gerar_dados_sinteticos(n_amostras=50)
        assert len(eventos) == 50

    @pytest.mark.unit
    def test_cada_evento_tem_campos_obrigatorios(self):
        """Todos os eventos gerados devem ter os campos do schema padrão."""
        campos_obrigatorios = {
            "timestamp", "event_type", "count", "bytes_sent",
            "bytes_received", "duration_ms", "protocol", "category",
            "http_status", "severity", "ml_score",
        }
        eventos = gerar_dados_sinteticos(n_amostras=10)

        for evento in eventos:
            for campo in campos_obrigatorios:
                assert campo in evento, f"Campo '{campo}' ausente no evento sintético"

    @pytest.mark.unit
    def test_tipos_dos_campos_numericos(self):
        """Campos numéricos devem ter os tipos corretos."""
        eventos = gerar_dados_sinteticos(n_amostras=20)

        for evento in eventos:
            assert isinstance(evento["count"], int)
            assert isinstance(evento["bytes_sent"], int)
            assert isinstance(evento["bytes_received"], int)
            assert isinstance(evento["duration_ms"], float)
            assert isinstance(evento["http_status"], int)

    @pytest.mark.unit
    def test_event_types_sao_validos(self):
        """event_type deve ser um dos tipos conhecidos."""
        tipos_validos = {"auth_success", "network_connection", "http_request"}
        eventos = gerar_dados_sinteticos(n_amostras=100)

        for evento in eventos:
            assert evento["event_type"] in tipos_validos

    @pytest.mark.unit
    def test_ml_score_inicial_e_menos_um(self):
        """ml_score deve ser -1 em todos os eventos sintéticos."""
        eventos = gerar_dados_sinteticos(n_amostras=10)
        for evento in eventos:
            assert evento["ml_score"] == -1

    @pytest.mark.unit
    def test_reproducibilidade_com_seed(self):
        """Duas chamadas devem gerar os mesmos dados (seed fixo)."""
        eventos_1 = gerar_dados_sinteticos(n_amostras=10)
        eventos_2 = gerar_dados_sinteticos(n_amostras=10)

        for e1, e2 in zip(eventos_1, eventos_2):
            assert e1["count"] == e2["count"]
            assert e1["event_type"] == e2["event_type"]

    @pytest.mark.unit
    def test_count_dentro_do_intervalo_esperado(self):
        """count deve estar entre 1 e 50 (limites do clip)."""
        eventos = gerar_dados_sinteticos(n_amostras=200)
        for evento in eventos:
            assert 1 <= evento["count"] <= 50, (
                f"count fora do intervalo: {evento['count']}"
            )


# =============================================================
# Testes de treinar_detector_anomalias()
# =============================================================

class TestTreinarDetectorAnomalias:
    """Testa o pipeline de treinamento do detector de anomalias."""

    @pytest.mark.unit
    def test_retorna_preprocessor_e_detector(self):
        """Deve retornar uma tupla (Preprocessor, AnomalyDetector)."""
        eventos = gerar_dados_sinteticos(n_amostras=50)
        preprocessor, detector = treinar_detector_anomalias(eventos)

        assert isinstance(preprocessor, Preprocessor)
        assert isinstance(detector, AnomalyDetector)

    @pytest.mark.unit
    def test_preprocessor_esta_treinado(self):
        eventos = gerar_dados_sinteticos(n_amostras=50)
        preprocessor, _ = treinar_detector_anomalias(eventos)

        assert preprocessor.is_fitted

    @pytest.mark.unit
    def test_detector_esta_treinado(self):
        eventos = gerar_dados_sinteticos(n_amostras=50)
        _, detector = treinar_detector_anomalias(eventos)

        assert detector.is_fitted

    @pytest.mark.unit
    def test_detector_consegue_fazer_predicoes_apos_treino(self):
        """Após o treinamento, o detector deve conseguir classificar novos eventos."""
        eventos = gerar_dados_sinteticos(n_amostras=50)
        preprocessor, detector = treinar_detector_anomalias(eventos)

        novos_eventos = gerar_dados_sinteticos(n_amostras=5)
        X = preprocessor.transform(novos_eventos)
        scores = detector.score_anomalia(X)

        assert len(scores) == 5
        assert all(0.0 <= s <= 1.0 for s in scores)

    @pytest.mark.unit
    def test_salva_artefatos_em_disco(self, tmp_path):
        """Os modelos treinados devem ser salvos em disco."""
        eventos = gerar_dados_sinteticos(n_amostras=50)

        with patch("ml.trainer.ARTIFACTS_DIR", tmp_path):
            with patch.object(Preprocessor, "salvar") as mock_salvar_prep:
                with patch.object(AnomalyDetector, "salvar") as mock_salvar_det:
                    treinar_detector_anomalias(eventos)

                    mock_salvar_prep.assert_called_once()
                    mock_salvar_det.assert_called_once()


# =============================================================
# Testes de treinar_classificador()
# =============================================================

class TestTreinarClassificador:
    """Testa o treinamento do classificador com fallback para dados sintéticos."""

    @pytest.mark.unit
    def test_retorna_classifier_treinado_sem_dataset(self):
        """
        Sem o dataset CICIDS2017, deve usar dados sintéticos
        e retornar um classificador treinado.
        """
        eventos = gerar_dados_sinteticos(n_amostras=100)
        preprocessor = Preprocessor()
        preprocessor.fit(eventos)

        # Garante que o arquivo de dataset não existe
        with patch("ml.trainer.DATASETS_DIR", Path("/caminho/inexistente")):
            classifier = treinar_classificador(preprocessor)

        assert isinstance(classifier, ThreatClassifier)
        assert classifier.is_fitted

    @pytest.mark.unit
    def test_classifier_consegue_predizer_apos_treino(self):
        """Classificador treinado deve conseguir fazer predições."""
        eventos = gerar_dados_sinteticos(n_amostras=100)
        preprocessor = Preprocessor()
        preprocessor.fit(eventos)

        with patch("ml.trainer.DATASETS_DIR", Path("/caminho/inexistente")):
            classifier = treinar_classificador(preprocessor)

        novos_eventos = gerar_dados_sinteticos(n_amostras=5)
        X = preprocessor.transform(novos_eventos)
        predicoes = classifier.predict(X)

        assert len(predicoes) == 5

    @pytest.mark.unit
    def test_usa_dataset_cicids_quando_disponivel(self, tmp_path):
        """Quando o dataset CICIDS2017 existe, deve usá-lo no treinamento."""
        # Cria um CSV mínimo simulando o formato do CICIDS2017
        dados = {
            "Feature1": [1.0, 2.0, 3.0, 4.0, 5.0] * 20,
            "Feature2": [0.5, 1.5, 2.5, 3.5, 4.5] * 20,
            "Label":    ["BENIGN", "PortScan", "DDoS", "FTP-Patator", "BENIGN"] * 20,
        }
        df = pd.DataFrame(dados)
        caminho_csv = tmp_path / "CICIDS2017_sample.csv"
        df.to_csv(caminho_csv, index=False)

        eventos = gerar_dados_sinteticos(n_amostras=100)
        preprocessor = Preprocessor()
        preprocessor.fit(eventos)

        with patch("ml.trainer.DATASETS_DIR", tmp_path):
            with patch("ml.trainer.ARTIFACTS_DIR", tmp_path):
                with patch.object(ThreatClassifier, "salvar"):
                    classifier = treinar_classificador(preprocessor)

        assert isinstance(classifier, ThreatClassifier)
        assert classifier.is_fitted


# =============================================================
# Testes de carregar_dataset_cicids()
# =============================================================

class TestCarregarDatasetCicids:
    """Testa o carregamento e parsing do dataset CICIDS2017."""

    @pytest.mark.unit
    def test_carrega_csv_e_retorna_features_e_labels(self, tmp_path):
        """Deve retornar DataFrame de features e Series de labels."""
        dados = {
            "Feature1": [1.0, 2.0, 3.0],
            "Feature2": [0.5, 1.5, 2.5],
            "Label":    ["BENIGN", "PortScan", "DDoS"],
        }
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        features, labels = carregar_dataset_cicids(caminho)

        assert isinstance(features, pd.DataFrame)
        assert isinstance(labels, pd.Series)

    @pytest.mark.unit
    def test_remove_coluna_label_das_features(self, tmp_path):
        """A coluna 'Label' não deve aparecer nas features."""
        dados = {
            "Feature1": [1.0, 2.0],
            "Label":    ["BENIGN", "PortScan"],
        }
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        features, _ = carregar_dataset_cicids(caminho)

        assert "Label" not in features.columns

    @pytest.mark.unit
    def test_mapeia_benign_para_zero(self, tmp_path):
        """Label 'BENIGN' deve ser mapeado para 0 (NORMAL)."""
        dados = {"Feature1": [1.0], "Label": ["BENIGN"]}
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        _, labels = carregar_dataset_cicids(caminho)

        assert labels.iloc[0] == 0

    @pytest.mark.unit
    def test_mapeia_portscan_para_dois(self, tmp_path):
        """Label 'PortScan' deve ser mapeado para 2 (PORT_SCAN)."""
        dados = {"Feature1": [1.0], "Label": ["PortScan"]}
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        _, labels = carregar_dataset_cicids(caminho)

        assert labels.iloc[0] == 2

    @pytest.mark.unit
    def test_descarta_labels_desconhecidos(self, tmp_path):
        """Labels não mapeados devem ser descartados."""
        dados = {
            "Feature1": [1.0, 2.0, 3.0],
            "Label":    ["BENIGN", "LabelDesconhecido", "PortScan"],
        }
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        features, labels = carregar_dataset_cicids(caminho)

        # Apenas BENIGN e PortScan devem sobrar
        assert len(labels) == 2

    @pytest.mark.unit
    def test_remove_espacos_dos_nomes_das_colunas(self, tmp_path):
        """Colunas com espaços (problema comum no CICIDS2017) devem ser limpas."""
        dados = {" Feature1 ": [1.0], " Label ": ["BENIGN"]}
        caminho = tmp_path / "test.csv"
        pd.DataFrame(dados).to_csv(caminho, index=False)

        features, _ = carregar_dataset_cicids(caminho)

        # Nenhuma coluna deve ter espaços
        assert all(" " not in col for col in features.columns)


# =============================================================
# Testes de carregar_eventos_elasticsearch()
# =============================================================

class TestCarregarEventosElasticsearch:
    """Testa o carregamento de eventos do Elasticsearch."""

    @pytest.mark.unit
    @patch("ml.trainer.Elasticsearch")
    def test_retorna_lista_de_eventos(self, mock_es_class):
        """Deve retornar lista de dicionários com os eventos."""
        # Simula resposta do Elasticsearch
        mock_es = MagicMock()
        mock_es_class.return_value = mock_es
        mock_es.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"event_type": "auth_failure", "count": 5}},
                    {"_source": {"event_type": "network_connection", "count": 1}},
                ]
            }
        }

        eventos = carregar_eventos_elasticsearch(limite=10)

        assert isinstance(eventos, list)
        assert len(eventos) == 2
        assert eventos[0]["event_type"] == "auth_failure"

    @pytest.mark.unit
    @patch("ml.trainer.Elasticsearch")
    def test_passa_limite_correto_na_query(self, mock_es_class):
        """O limite informado deve ser passado na query ao Elasticsearch."""
        mock_es = MagicMock()
        mock_es_class.return_value = mock_es
        mock_es.search.return_value = {"hits": {"hits": []}}

        carregar_eventos_elasticsearch(limite=999)

        chamada = mock_es.search.call_args
        assert chamada[1]["body"]["size"] == 999


# =============================================================
# Testes de main()
# =============================================================

class TestMain:
    """Testa a orquestração completa do treinamento."""

    @pytest.mark.unit
    @patch("ml.trainer.treinar_classificador")
    @patch("ml.trainer.treinar_detector_anomalias")
    @patch("ml.trainer.carregar_eventos_elasticsearch")
    def test_main_usa_elasticsearch_quando_disponivel(
        self, mock_es, mock_detector, mock_classifier
    ):
        """Quando o Elasticsearch retorna dados suficientes, deve usá-los."""
        eventos_es = gerar_dados_sinteticos(n_amostras=1_500)
        mock_es.return_value = eventos_es

        preprocessor_mock = MagicMock()
        preprocessor_mock.is_fitted = True
        detector_mock = MagicMock()
        mock_detector.return_value = (preprocessor_mock, detector_mock)
        mock_classifier.return_value = MagicMock()

        main()

        mock_es.assert_called_once()
        mock_detector.assert_called_once()
        mock_classifier.assert_called_once()

    @pytest.mark.unit
    @patch("ml.trainer.gerar_dados_sinteticos")
    @patch("ml.trainer.treinar_classificador")
    @patch("ml.trainer.treinar_detector_anomalias")
    @patch("ml.trainer.carregar_eventos_elasticsearch")
    def test_main_usa_dados_sinteticos_quando_es_falha(
        self, mock_es, mock_detector, mock_classifier, mock_sinteticos
    ):
        """Quando o Elasticsearch falha, deve usar dados sintéticos como fallback."""
        mock_es.side_effect = Exception("Elasticsearch indisponível")
        mock_sinteticos.return_value = gerar_dados_sinteticos(n_amostras=100)

        preprocessor_mock = MagicMock()
        preprocessor_mock.is_fitted = True
        mock_detector.return_value = (preprocessor_mock, MagicMock())
        mock_classifier.return_value = MagicMock()

        # Não deve lançar exceção
        main()

        mock_sinteticos.assert_called_once()
        mock_detector.assert_called_once()

    @pytest.mark.unit
    @patch("ml.trainer.gerar_dados_sinteticos")
    @patch("ml.trainer.treinar_classificador")
    @patch("ml.trainer.treinar_detector_anomalias")
    @patch("ml.trainer.carregar_eventos_elasticsearch")
    def test_main_complementa_dados_insuficientes_do_es(
        self, mock_es, mock_detector, mock_classifier, mock_sinteticos
    ):
        """
        Quando o ES retorna menos de 1000 eventos,
        deve complementar com dados sintéticos.
        """
        # ES retorna apenas 100 eventos (insuficiente)
        mock_es.return_value = gerar_dados_sinteticos(n_amostras=100)
        mock_sinteticos.return_value = gerar_dados_sinteticos(n_amostras=9_900)

        preprocessor_mock = MagicMock()
        preprocessor_mock.is_fitted = True
        mock_detector.return_value = (preprocessor_mock, MagicMock())
        mock_classifier.return_value = MagicMock()

        main()

        # Deve ter chamado gerar_dados_sinteticos para complementar
        mock_sinteticos.assert_called_once()
