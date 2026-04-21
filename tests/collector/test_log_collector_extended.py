"""
Testes Estendidos do Coletor de Logs — AI-Powered Threat Hunter
===============================================================
Cobre as partes não testadas anteriormente:
    - enviar_evento(): serialização e envio via socket
    - conectar_logstash(): conexão TCP e reconexão com backoff
    - monitorar_arquivo(): leitura de arquivo e envio de eventos
    - session_closed: tipo de evento ainda não coberto
    - main(): inicialização do coletor

Todas as dependências externas (socket, filesystem, time.sleep)
são substituídas por mocks para que os testes rodem sem
infraestrutura real.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open, call

from collector.syslog.log_collector import (
    normalizar_evento,
    enviar_evento,
    conectar_logstash,
    monitorar_arquivo,
    main,
    LOGSTASH_HOST,
    LOGSTASH_PORT,
)


# =============================================================
# Testes de session_closed (tipo não coberto anteriormente)
# =============================================================

class TestNormalizacaoSessionClosed:
    """Testa detecção de encerramento de sessão."""

    @pytest.mark.unit
    def test_detecta_session_closed(self):
        linha = "Apr 19 14:35:01 web-01 sshd[1234]: pam_unix(sshd:session): session closed for user deploy"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "session_closed"

    @pytest.mark.unit
    def test_extrai_username_do_session_closed(self):
        linha = "Apr 19 14:35:01 web-01 sshd[1234]: pam_unix(sshd:session): session closed for user ubuntu"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["username"] == "ubuntu"

    @pytest.mark.unit
    def test_session_closed_nao_tem_source_ip(self):
        """session_closed não tem IP de origem — campo não deve existir."""
        linha = "Apr 19 14:35:01 web-01 sshd[1234]: pam_unix(sshd:session): session closed for user deploy"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert "source_ip" not in evento


# =============================================================
# Testes de enviar_evento()
# =============================================================

class TestEnviarEvento:
    """Testa a serialização e envio de eventos via socket TCP."""

    @pytest.mark.unit
    def test_envia_payload_json_com_newline(self, evento_auth_failure):
        """O payload enviado deve ser JSON terminado com newline."""
        sock_mock = MagicMock()

        enviar_evento(sock_mock, evento_auth_failure)

        # Verifica que sendall foi chamado
        sock_mock.sendall.assert_called_once()

        # Extrai o payload enviado e verifica o formato
        payload_bytes = sock_mock.sendall.call_args[0][0]
        payload_str = payload_bytes.decode("utf-8")

        assert payload_str.endswith("\n"), "Payload deve terminar com newline"

    @pytest.mark.unit
    def test_payload_e_json_valido(self, evento_auth_failure):
        """O payload enviado deve ser JSON válido e deserializável."""
        sock_mock = MagicMock()

        enviar_evento(sock_mock, evento_auth_failure)

        payload_bytes = sock_mock.sendall.call_args[0][0]
        payload_str = payload_bytes.decode("utf-8").strip()

        # Não deve lançar exceção
        dados = json.loads(payload_str)
        assert dados["event_type"] == evento_auth_failure["event_type"]

    @pytest.mark.unit
    def test_payload_preserva_todos_os_campos(self, evento_auth_failure):
        """Todos os campos do evento devem estar presentes no payload."""
        sock_mock = MagicMock()

        enviar_evento(sock_mock, evento_auth_failure)

        payload_bytes = sock_mock.sendall.call_args[0][0]
        dados = json.loads(payload_bytes.decode("utf-8").strip())

        for campo in ["event_type", "source_ip", "username", "timestamp"]:
            assert campo in dados, f"Campo '{campo}' ausente no payload"

    @pytest.mark.unit
    def test_envia_evento_sem_source_ip(self):
        """Eventos sem source_ip (ex: session_closed) não devem lançar exceção."""
        sock_mock = MagicMock()
        evento = {
            "event_type": "session_closed",
            "username": "deploy",
            "timestamp": "2026-04-19T14:35:00Z",
            "severity": None,
            "ml_score": -1,
            "source": "/var/log/auth.log",
            "raw_log": "session closed for user deploy",
        }

        # Não deve lançar exceção
        enviar_evento(sock_mock, evento)
        sock_mock.sendall.assert_called_once()


# =============================================================
# Testes de conectar_logstash()
# =============================================================

class TestConectarLogstash:
    """Testa a conexão TCP com o Logstash e o mecanismo de reconexão."""

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.socket.socket")
    def test_conecta_com_sucesso_na_primeira_tentativa(self, mock_socket_class):
        """Deve retornar o socket na primeira tentativa quando o Logstash está disponível."""
        sock_mock = MagicMock()
        mock_socket_class.return_value = sock_mock

        resultado = conectar_logstash()

        # Verifica que connect foi chamado com host e porta corretos
        sock_mock.connect.assert_called_once_with((LOGSTASH_HOST, LOGSTASH_PORT))
        assert resultado is sock_mock

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.time.sleep")
    @patch("collector.syslog.log_collector.socket.socket")
    def test_reconecta_apos_falha(self, mock_socket_class, mock_sleep):
        """
        Deve tentar reconectar quando a primeira tentativa falha.
        Simula: primeira tentativa falha → segunda tentativa sucesso.
        """
        sock_falha = MagicMock()
        sock_falha.connect.side_effect = [ConnectionRefusedError, None]
        mock_socket_class.return_value = sock_falha

        resultado = conectar_logstash()

        # connect deve ter sido chamado duas vezes
        assert sock_falha.connect.call_count == 2
        # sleep deve ter sido chamado durante o backoff
        mock_sleep.assert_called_once()

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.time.sleep")
    @patch("collector.syslog.log_collector.socket.socket")
    def test_backoff_exponencial(self, mock_socket_class, mock_sleep):
        """
        O tempo de espera entre tentativas deve crescer exponencialmente.
        Tentativa 0 → espera 1s, tentativa 1 → espera 2s, tentativa 2 → espera 4s.
        """
        sock_mock = MagicMock()
        # Falha 3 vezes, depois conecta
        sock_mock.connect.side_effect = [
            ConnectionRefusedError,
            ConnectionRefusedError,
            ConnectionRefusedError,
            None,
        ]
        mock_socket_class.return_value = sock_mock

        conectar_logstash()

        # Verifica os tempos de espera: 1, 2, 4 segundos
        esperas = [c[0][0] for c in mock_sleep.call_args_list]
        assert esperas == [1, 2, 4], f"Backoff esperado [1, 2, 4], obtido {esperas}"

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.time.sleep")
    @patch("collector.syslog.log_collector.socket.socket")
    def test_backoff_limitado_a_60_segundos(self, mock_socket_class, mock_sleep):
        """O backoff não deve ultrapassar 60 segundos."""
        sock_mock = MagicMock()
        # Falha 10 vezes (2^10 = 1024, mas deve ser limitado a 60)
        sock_mock.connect.side_effect = [ConnectionRefusedError] * 10 + [None]
        mock_socket_class.return_value = sock_mock

        conectar_logstash()

        esperas = [c[0][0] for c in mock_sleep.call_args_list]
        assert max(esperas) <= 60, f"Backoff máximo deve ser 60s, obtido {max(esperas)}s"


# =============================================================
# Testes de monitorar_arquivo()
# =============================================================

class TestMonitorarArquivo:
    """Testa o monitoramento de arquivos de log em tempo real."""

    @pytest.mark.unit
    def test_ignora_arquivo_inexistente(self, tmp_path):
        """Arquivo que não existe deve ser ignorado sem lançar exceção."""
        sock_mock = MagicMock()
        caminho_inexistente = tmp_path / "nao_existe.log"

        # Não deve lançar exceção
        monitorar_arquivo(caminho_inexistente, sock_mock)

        # Nenhum evento deve ter sido enviado
        sock_mock.sendall.assert_not_called()

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.time.sleep")
    def test_processa_linha_reconhecida_e_envia(self, mock_sleep, tmp_path):
        """
        Linha de log reconhecida deve ser normalizada e enviada ao Logstash.
        Usa um arquivo que cresce após o seek para simular tail -f.
        """
        sock_mock = MagicMock()
        log_file = tmp_path / "auth.log"
        linha_valida = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2\n"

        # Cria o arquivo vazio — monitorar_arquivo vai fazer seek(0,2) para o final
        log_file.write_text("")

        # Após o primeiro sleep (sem novas linhas), escreve a linha e para o loop
        chamadas_sleep = [0]

        def sleep_side_effect(_):
            chamadas_sleep[0] += 1
            if chamadas_sleep[0] == 1:
                # Escreve a linha no arquivo para ser lida na próxima iteração
                with open(log_file, "a") as f:
                    f.write(linha_valida)
            elif chamadas_sleep[0] == 2:
                raise StopIteration

        mock_sleep.side_effect = sleep_side_effect

        with pytest.raises(StopIteration):
            monitorar_arquivo(log_file, sock_mock)

        sock_mock.sendall.assert_called_once()
        payload = json.loads(sock_mock.sendall.call_args[0][0].decode().strip())
        assert payload["event_type"] == "auth_failure"

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.time.sleep")
    def test_ignora_linha_nao_reconhecida(self, mock_sleep, tmp_path):
        """Linha irrelevante não deve gerar envio ao Logstash."""
        sock_mock = MagicMock()
        log_file = tmp_path / "syslog"
        log_file.write_text("")

        chamadas_sleep = [0]

        def sleep_side_effect(_):
            chamadas_sleep[0] += 1
            if chamadas_sleep[0] == 1:
                with open(log_file, "a") as f:
                    f.write("Apr 19 14:30:01 web-01 systemd[1]: Started cron.\n")
            elif chamadas_sleep[0] == 2:
                raise StopIteration

        mock_sleep.side_effect = sleep_side_effect

        with pytest.raises(StopIteration):
            monitorar_arquivo(log_file, sock_mock)

        sock_mock.sendall.assert_not_called()

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.conectar_logstash")
    @patch("collector.syslog.log_collector.time.sleep")
    def test_reconecta_quando_socket_quebra(self, mock_sleep, mock_conectar, tmp_path):
        """Quando o socket quebra durante o envio, deve reconectar e reenviar."""
        sock_original = MagicMock()
        sock_original.sendall.side_effect = BrokenPipeError

        sock_novo = MagicMock()
        mock_conectar.return_value = sock_novo

        log_file = tmp_path / "auth.log"
        log_file.write_text("")

        chamadas_sleep = [0]

        def sleep_side_effect(_):
            chamadas_sleep[0] += 1
            if chamadas_sleep[0] == 1:
                with open(log_file, "a") as f:
                    f.write("Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
            elif chamadas_sleep[0] == 2:
                raise StopIteration

        mock_sleep.side_effect = sleep_side_effect

        with pytest.raises(StopIteration):
            monitorar_arquivo(log_file, sock_original)

        mock_conectar.assert_called_once()
        sock_novo.sendall.assert_called_once()


# =============================================================
# Testes de main()
# =============================================================

class TestMain:
    """Testa a inicialização do coletor."""

    @pytest.mark.unit
    @patch("collector.syslog.log_collector.monitorar_arquivo")
    @patch("collector.syslog.log_collector.conectar_logstash")
    def test_main_conecta_e_monitora_arquivos(self, mock_conectar, mock_monitorar):
        """main() deve conectar ao Logstash e iniciar monitoramento dos arquivos."""
        sock_mock = MagicMock()
        mock_conectar.return_value = sock_mock

        main()

        # Deve ter conectado ao Logstash
        mock_conectar.assert_called_once()

        # Deve ter chamado monitorar_arquivo para cada arquivo configurado
        assert mock_monitorar.call_count >= 1

        # Verifica que o socket foi passado para o monitoramento
        for chamada in mock_monitorar.call_args_list:
            assert chamada[0][1] is sock_mock
