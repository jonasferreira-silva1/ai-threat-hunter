"""
Testes do Coletor de Logs — AI-Powered Threat Hunter
=====================================================
Cobre:
    - Normalização de cada tipo de evento suportado
    - Comportamento com linhas não reconhecidas
    - Campos obrigatórios do schema padrão
    - Serialização JSON para envio ao Logstash
"""

import json
import pytest
from collector.syslog.log_collector import normalizar_evento


# =============================================================
# Campos obrigatórios em todo evento normalizado
# =============================================================
CAMPOS_OBRIGATORIOS = {"timestamp", "event_type", "source", "raw_log", "severity", "ml_score"}


# =============================================================
# Testes de normalização por tipo de evento
# =============================================================

class TestNormalizacaoAuthFailure:
    """Testa detecção e normalização de falhas de autenticação."""

    @pytest.mark.unit
    def test_detecta_falha_ssh_por_senha(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "auth_failure"

    @pytest.mark.unit
    def test_detecta_falha_ssh_usuario_invalido(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "auth_failure"
        assert evento["username"] == "admin"
        assert evento["source_ip"] == "10.0.0.1"

    @pytest.mark.unit
    def test_extrai_ip_de_origem_corretamente(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 198.51.100.42 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["source_ip"] == "198.51.100.42"

    @pytest.mark.unit
    def test_extrai_username_corretamente(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for deploy from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["username"] == "deploy"


class TestNormalizacaoAuthSuccess:
    """Testa detecção e normalização de autenticações bem-sucedidas."""

    @pytest.mark.unit
    def test_detecta_login_bem_sucedido(self):
        linha = "Apr 19 14:32:01 web-01 sshd[1234]: Accepted password for deploy from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "auth_success"
        assert evento["username"] == "deploy"
        assert evento["source_ip"] == "203.0.113.5"

    @pytest.mark.unit
    def test_detecta_login_por_chave_publica(self):
        linha = "Apr 19 14:32:01 web-01 sshd[1234]: Accepted publickey for ubuntu from 192.168.1.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "auth_success"


class TestNormalizacaoPrivilegeEscalation:
    """Testa detecção de escalonamento de privilégios via sudo."""

    @pytest.mark.unit
    def test_detecta_sudo(self):
        linha = "Apr 19 14:33:01 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/su"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        assert evento["event_type"] == "privilege_escalation"
        assert evento["username"] == "deploy"

    @pytest.mark.unit
    def test_extrai_comando_executado(self):
        linha = "Apr 19 14:33:01 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert "/bin/bash" in evento["command"]


# =============================================================
# Testes do schema padrão
# =============================================================

class TestSchemaPadrao:
    """Garante que todos os eventos seguem o schema mínimo obrigatório."""

    @pytest.mark.unit
    @pytest.mark.parametrize("linha", [
        "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2",
        "Apr 19 14:32:01 web-01 sshd[1234]: Accepted password for deploy from 203.0.113.5 port 22 ssh2",
        "Apr 19 14:33:01 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/su",
    ])
    def test_campos_obrigatorios_presentes(self, linha):
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento is not None
        for campo in CAMPOS_OBRIGATORIOS:
            assert campo in evento, f"Campo obrigatório ausente: '{campo}'"

    @pytest.mark.unit
    def test_ml_score_inicial_e_menos_um(self):
        """ml_score deve ser -1 (não processado) ao sair do coletor."""
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["ml_score"] == -1

    @pytest.mark.unit
    def test_severity_inicial_e_none(self):
        """severity deve ser None ao sair do coletor — será preenchido pelo ML."""
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["severity"] is None

    @pytest.mark.unit
    def test_raw_log_preserva_linha_original(self):
        """raw_log deve conter a linha original para auditoria."""
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["raw_log"] == linha.strip()

    @pytest.mark.unit
    def test_source_registra_arquivo_de_origem(self):
        """source deve registrar de qual arquivo o log veio."""
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        assert evento["source"] == "/var/log/auth.log"


# =============================================================
# Testes de linhas não reconhecidas
# =============================================================

class TestLinhasNaoReconhecidas:
    """Garante que linhas irrelevantes são descartadas silenciosamente."""

    @pytest.mark.unit
    def test_linha_irrelevante_retorna_none(self):
        linha = "Apr 19 14:30:01 web-01 systemd[1]: Started Daily apt download activities."
        evento = normalizar_evento(linha, "/var/log/syslog")

        assert evento is None

    @pytest.mark.unit
    def test_linha_vazia_retorna_none(self):
        assert normalizar_evento("", "/var/log/auth.log") is None

    @pytest.mark.unit
    def test_linha_apenas_espacos_retorna_none(self):
        assert normalizar_evento("   ", "/var/log/auth.log") is None


# =============================================================
# Testes de serialização JSON
# =============================================================

class TestSerializacaoJSON:
    """Garante que os eventos podem ser serializados para envio ao Logstash."""

    @pytest.mark.unit
    def test_evento_e_serializavel_em_json(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        # Não deve lançar exceção
        payload = json.dumps(evento)
        assert isinstance(payload, str)

    @pytest.mark.unit
    def test_json_deserializado_mantem_valores(self):
        linha = "Apr 19 14:30:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        evento = normalizar_evento(linha, "/var/log/auth.log")

        reconstruido = json.loads(json.dumps(evento))
        assert reconstruido["event_type"] == evento["event_type"]
        assert reconstruido["source_ip"] == evento["source_ip"]
