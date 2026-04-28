"""
Testes unitários e de propriedade para IsolationManager.

Cobre:
    - isolar_host() com subprocess mockado (sucesso)
    - desfazer_isolamento() restaura estado anterior
    - Falha retorna status="failed" sem exceção
    - Host isolado aparece no estado interno _hosts_isolados
    - Após desfazer_isolamento(), host não aparece mais em _hosts_isolados
    - Property 18: isolamento é reversível (round-trip)
    - Property 19: IsolationManager resiliente a falhas

Requisitos: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from hypothesis import given, settings, strategies as st

from response.isolation import IsolationManager


# =============================================================
# Helpers
# =============================================================

def _hostname_valido():
    """Estratégia Hypothesis para gerar hostnames/IPs válidos."""
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    )


def _mock_subprocess_sucesso():
    """Cria mock de subprocess.run que sempre retorna returncode=0."""
    resultado = MagicMock()
    resultado.returncode = 0
    resultado.stdout = ""
    resultado.stderr = ""
    return MagicMock(return_value=resultado)


def _mock_subprocess_falha(returncode: int = 1, stderr: str = "iptables: Operation not permitted"):
    """Cria mock de subprocess.run que retorna falha."""
    resultado = MagicMock()
    resultado.returncode = returncode
    resultado.stdout = ""
    resultado.stderr = stderr
    return MagicMock(return_value=resultado)


# =============================================================
# Testes unitários — isolar_host()
# =============================================================

class TestIsolarHost:
    """Testes para IsolationManager.isolar_host()."""

    def test_isolar_host_sucesso(self, monkeypatch):
        """isolar_host() retorna status='success' quando subprocess tem sucesso."""
        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        acao = iso.isolar_host("192.168.1.50")

        assert acao.status == "success"
        assert acao.tipo == "host_isolation"
        assert acao.alvo == "192.168.1.50"
        assert acao.erro is None

    def test_isolar_host_executa_tres_regras_iptables(self, monkeypatch):
        """isolar_host() executa exatamente 3 comandos iptables."""
        mock_run = _mock_subprocess_sucesso()
        monkeypatch.setattr("subprocess.run", mock_run)

        iso = IsolationManager()
        iso.isolar_host("10.0.0.5")

        assert mock_run.call_count == 3

    def test_isolar_host_permite_porta_22(self, monkeypatch):
        """isolar_host() adiciona regra ACCEPT para porta 22 antes do DROP."""
        chamadas = []

        def side_effect(cmd, **kwargs):
            chamadas.append(cmd)
            resultado = MagicMock()
            resultado.returncode = 0
            resultado.stdout = ""
            resultado.stderr = ""
            return resultado

        monkeypatch.setattr("subprocess.run", MagicMock(side_effect=side_effect))

        iso = IsolationManager()
        iso.isolar_host("172.16.0.10")

        # Primeira regra deve ser ACCEPT na porta 22
        assert "--dport" in chamadas[0]
        assert "22" in chamadas[0]
        assert "ACCEPT" in chamadas[0]

    def test_isolar_host_adiciona_ao_estado_interno(self, monkeypatch):
        """Host isolado aparece em _hosts_isolados após isolar_host()."""
        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        iso.isolar_host("10.10.10.10")

        assert "10.10.10.10" in iso._hosts_isolados

    def test_isolar_host_falha_permissao(self, monkeypatch, mock_subprocess_falha_permissao):
        """Falha de permissão retorna status='failed' sem lançar exceção."""
        iso = IsolationManager()
        acao = iso.isolar_host("1.2.3.4")

        assert acao.status == "failed"
        assert acao.erro is not None

    def test_isolar_host_falha_comando_nao_encontrado(self, monkeypatch, mock_subprocess_falha_comando):
        """FileNotFoundError retorna status='failed' sem lançar exceção."""
        iso = IsolationManager()
        acao = iso.isolar_host("5.6.7.8")

        assert acao.status == "failed"
        assert acao.erro is not None

    def test_isolar_host_falha_nao_adiciona_ao_estado(self, monkeypatch, mock_subprocess_falha_permissao):
        """Host não é adicionado a _hosts_isolados quando isolar_host() falha."""
        iso = IsolationManager()
        iso.isolar_host("9.9.9.9")

        assert "9.9.9.9" not in iso._hosts_isolados

    def test_isolar_host_timestamp_iso8601(self, monkeypatch):
        """ResponseAction retornado tem timestamp em formato ISO 8601 UTC."""
        from datetime import datetime

        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        acao = iso.isolar_host("1.1.1.1")

        ts = acao.timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None


# =============================================================
# Testes unitários — desfazer_isolamento()
# =============================================================

class TestDesfazerIsolamento:
    """Testes para IsolationManager.desfazer_isolamento()."""

    def test_desfazer_isolamento_sucesso(self, monkeypatch):
        """desfazer_isolamento() retorna status='success' quando subprocess tem sucesso."""
        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        # Isola primeiro
        iso.isolar_host("192.168.1.50")
        # Desfaz
        acao = iso.desfazer_isolamento("192.168.1.50")

        assert acao.status == "success"
        assert acao.tipo == "host_isolation_undo"
        assert acao.alvo == "192.168.1.50"
        assert acao.erro is None

    def test_desfazer_isolamento_remove_do_estado_interno(self, monkeypatch):
        """Após desfazer_isolamento(), host não aparece mais em _hosts_isolados."""
        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        iso.isolar_host("10.0.0.1")
        assert "10.0.0.1" in iso._hosts_isolados

        iso.desfazer_isolamento("10.0.0.1")
        assert "10.0.0.1" not in iso._hosts_isolados

    def test_desfazer_isolamento_executa_tres_remocoes(self, monkeypatch):
        """desfazer_isolamento() executa exatamente 3 comandos iptables -D."""
        mock_run = _mock_subprocess_sucesso()
        monkeypatch.setattr("subprocess.run", mock_run)

        iso = IsolationManager()
        # isolar_host usa 3 chamadas, desfazer_isolamento usa mais 3
        iso.isolar_host("172.16.0.1")
        mock_run.reset_mock()

        iso.desfazer_isolamento("172.16.0.1")
        assert mock_run.call_count == 3

    def test_desfazer_isolamento_usa_flag_delete(self, monkeypatch):
        """desfazer_isolamento() usa flag -D (delete) nos comandos iptables."""
        chamadas = []

        def side_effect(cmd, **kwargs):
            chamadas.append(cmd)
            resultado = MagicMock()
            resultado.returncode = 0
            resultado.stdout = ""
            resultado.stderr = ""
            return resultado

        monkeypatch.setattr("subprocess.run", MagicMock(side_effect=side_effect))

        iso = IsolationManager()
        iso.isolar_host("10.0.0.2")
        chamadas.clear()

        iso.desfazer_isolamento("10.0.0.2")

        # Todos os comandos de remoção devem usar -D
        for cmd in chamadas:
            assert "-D" in cmd

    def test_desfazer_isolamento_falha_permissao(self, monkeypatch, mock_subprocess_falha_permissao):
        """Falha de permissão ao desfazer retorna status='failed' sem exceção."""
        iso = IsolationManager()
        acao = iso.desfazer_isolamento("9.9.9.9")

        assert acao.status == "failed"
        assert acao.erro is not None

    def test_desfazer_isolamento_falha_comando_nao_encontrado(self, monkeypatch, mock_subprocess_falha_comando):
        """FileNotFoundError ao desfazer retorna status='failed' sem exceção."""
        iso = IsolationManager()
        acao = iso.desfazer_isolamento("9.9.9.9")

        assert acao.status == "failed"

    def test_desfazer_isolamento_host_nao_isolado(self, monkeypatch):
        """desfazer_isolamento() em host não isolado ainda tenta remover regras."""
        monkeypatch.setattr("subprocess.run", _mock_subprocess_sucesso())

        iso = IsolationManager()
        # Chama sem ter isolado antes — não deve lançar exceção
        acao = iso.desfazer_isolamento("99.99.99.99")

        assert acao.status == "success"
        assert "99.99.99.99" not in iso._hosts_isolados


# =============================================================
# Property-Based Tests — 9.3 e 9.4
# =============================================================

class TestPropriedades:
    """
    Testes de propriedade para IsolationManager.

    **Validates: Requirements 8.2, 8.3, 8.4**
    """

    @given(hostname=_hostname_valido())
    @settings(max_examples=30)
    def test_property_18_isolamento_reversivel(self, hostname):
        """
        Property 18: IsolationManager isolamento é reversível (round-trip).

        Para qualquer hostname válido, após isolar_host() seguido de
        desfazer_isolamento(), o host não deve mais estar em _hosts_isolados,
        representando restauração ao estado anterior.

        **Validates: Requirements 8.2, 8.4**
        """
        resultado_ok = MagicMock()
        resultado_ok.returncode = 0
        resultado_ok.stdout = ""
        resultado_ok.stderr = ""

        with patch("subprocess.run", return_value=resultado_ok):
            iso = IsolationManager()

            acao_isolar = iso.isolar_host(hostname)
            assert acao_isolar.status == "success"
            assert hostname in iso._hosts_isolados

            acao_desfazer = iso.desfazer_isolamento(hostname)
            assert acao_desfazer.status == "success"
            assert hostname not in iso._hosts_isolados

    @given(hostname=_hostname_valido())
    @settings(max_examples=30)
    def test_property_19_resiliente_a_falhas(self, hostname):
        """
        Property 19: IsolationManager é resiliente a falhas.

        Para qualquer hostname, se isolar_host() falhar (subprocess com erro),
        deve retornar ResponseAction com status="failed" sem lançar exceção.

        **Validates: Requirements 8.3**
        """
        resultado_falha = MagicMock()
        resultado_falha.returncode = 1
        resultado_falha.stdout = ""
        resultado_falha.stderr = "iptables: Operation not permitted"

        with patch("subprocess.run", return_value=resultado_falha):
            iso = IsolationManager()
            acao = iso.isolar_host(hostname)

        assert acao.status == "failed"
        assert acao.erro is not None
        assert hostname not in iso._hosts_isolados

    @given(hostname=_hostname_valido())
    @settings(max_examples=30)
    def test_property_19b_resiliente_file_not_found(self, hostname):
        """
        Property 19 (variante): IsolationManager resiliente a FileNotFoundError.

        Para qualquer hostname, se iptables não estiver disponível,
        isolar_host() retorna status="failed" sem lançar exceção.

        **Validates: Requirements 8.3**
        """
        with patch("subprocess.run", side_effect=FileNotFoundError("iptables not found")):
            iso = IsolationManager()
            acao = iso.isolar_host(hostname)

        assert acao.status == "failed"
        assert acao.erro is not None
        assert hostname not in iso._hosts_isolados
