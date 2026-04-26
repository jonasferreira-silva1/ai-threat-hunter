"""
Testes unitários e de propriedade para FirewallManager.

Cobre:
    - bloquear_ip() com subprocess mockado (sucesso)
    - Idempotência: segunda chamada com mesmo IP retorna status="success"
    - desbloquear_ip() remove a regra
    - listar_bloqueados() reflete estado atual
    - Falha de permissão retorna status="failed" sem exceção
    - Falha por FileNotFoundError retorna status="failed"
    - Property 14: bloquear_ip é idempotente
    - Property 15: FirewallManager persiste IPs bloqueados
    - Property 16: block/unblock é round-trip
    - Property 17: resiliente a falhas de permissão

Requisitos: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
"""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from hypothesis import given, settings, strategies as st

from response.firewall import FirewallManager


# =============================================================
# Helpers
# =============================================================

def _ip_valido():
    """Estratégia Hypothesis para gerar IPs IPv4 válidos."""
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    )


def _make_subprocess_mock(returncode_check: int = 1, returncode_action: int = 0):
    """
    Cria um mock de subprocess.run que:
    - Retorna returncode_check para iptables -C (verificação de existência)
    - Retorna returncode_action para iptables -I / -D (ação)
    """
    def side_effect(cmd, **kwargs):
        resultado = MagicMock()
        resultado.stdout = ""
        resultado.stderr = ""
        if "-C" in cmd:
            resultado.returncode = returncode_check
        else:
            resultado.returncode = returncode_action
        return resultado

    return MagicMock(side_effect=side_effect)


# =============================================================
# Testes unitários — 8.2
# =============================================================

class TestBloquearIp:
    """Testes para FirewallManager.bloquear_ip()."""

    def test_bloquear_ip_sucesso(self, tmp_path, monkeypatch):
        """bloquear_ip() retorna status='success' quando subprocess tem sucesso."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )
        mock_run = _make_subprocess_mock(returncode_check=1, returncode_action=0)
        monkeypatch.setattr("subprocess.run", mock_run)

        fw = FirewallManager()
        acao = fw.bloquear_ip("192.168.1.100")

        assert acao.status == "success"
        assert acao.tipo == "firewall_block"
        assert acao.alvo == "192.168.1.100"
        assert acao.erro is None

    def test_bloquear_ip_persiste_no_arquivo(self, tmp_path, monkeypatch):
        """bloquear_ip() persiste o IP no arquivo de configuração."""
        arquivo = tmp_path / "blocked_ips.conf"
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)
        mock_run = _make_subprocess_mock(returncode_check=1, returncode_action=0)
        monkeypatch.setattr("subprocess.run", mock_run)

        fw = FirewallManager()
        fw.bloquear_ip("10.0.0.1")

        assert arquivo.exists()
        assert "10.0.0.1" in arquivo.read_text()

    def test_bloquear_ip_idempotente_segunda_chamada(self, tmp_path, monkeypatch):
        """Segunda chamada com mesmo IP retorna status='success' sem criar regra duplicada."""
        arquivo = tmp_path / "blocked_ips.conf"
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)

        # Primeira chamada: -C retorna 1 (não existe), -I retorna 0 (sucesso)
        # Segunda chamada: -C retorna 0 (já existe) → idempotente
        chamadas = {"count": 0}

        def side_effect(cmd, **kwargs):
            resultado = MagicMock()
            resultado.stdout = ""
            resultado.stderr = ""
            if "-C" in cmd:
                # Primeira verificação: não existe; segunda: já existe
                resultado.returncode = 1 if chamadas["count"] == 0 else 0
            else:
                resultado.returncode = 0
                chamadas["count"] += 1
            return resultado

        monkeypatch.setattr("subprocess.run", MagicMock(side_effect=side_effect))

        fw = FirewallManager()
        acao1 = fw.bloquear_ip("172.16.0.1")
        acao2 = fw.bloquear_ip("172.16.0.1")

        assert acao1.status == "success"
        assert acao2.status == "success"
        assert acao2.detalhes.get("idempotente") is True

    def test_bloquear_ip_falha_permissao(self, tmp_path, monkeypatch, mock_subprocess_falha_permissao):
        """Falha de permissão retorna status='failed' sem lançar exceção."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )

        fw = FirewallManager()
        acao = fw.bloquear_ip("1.2.3.4")

        assert acao.status == "failed"
        assert acao.erro is not None

    def test_bloquear_ip_falha_comando_nao_encontrado(self, tmp_path, monkeypatch, mock_subprocess_falha_comando):
        """FileNotFoundError retorna status='failed' sem lançar exceção."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )

        fw = FirewallManager()
        acao = fw.bloquear_ip("5.6.7.8")

        assert acao.status == "failed"
        assert acao.erro is not None


class TestDesbloquearIp:
    """Testes para FirewallManager.desbloquear_ip()."""

    def test_desbloquear_ip_sucesso(self, tmp_path, monkeypatch):
        """desbloquear_ip() retorna status='success' e remove do arquivo."""
        arquivo = tmp_path / "blocked_ips.conf"
        arquivo.write_text("10.0.0.5\n")
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)

        resultado = MagicMock()
        resultado.returncode = 0
        resultado.stdout = ""
        resultado.stderr = ""
        monkeypatch.setattr("subprocess.run", MagicMock(return_value=resultado))

        fw = FirewallManager()
        acao = fw.desbloquear_ip("10.0.0.5")

        assert acao.status == "success"
        assert acao.tipo == "firewall_unblock"
        assert "10.0.0.5" not in arquivo.read_text()

    def test_desbloquear_ip_falha_permissao(self, tmp_path, monkeypatch, mock_subprocess_falha_permissao):
        """Falha de permissão ao desbloquear retorna status='failed' sem exceção."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )

        fw = FirewallManager()
        acao = fw.desbloquear_ip("9.9.9.9")

        assert acao.status == "failed"
        assert acao.erro is not None

    def test_desbloquear_ip_falha_comando_nao_encontrado(self, tmp_path, monkeypatch, mock_subprocess_falha_comando):
        """FileNotFoundError ao desbloquear retorna status='failed' sem exceção."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )

        fw = FirewallManager()
        acao = fw.desbloquear_ip("9.9.9.9")

        assert acao.status == "failed"


class TestListarBloqueados:
    """Testes para FirewallManager.listar_bloqueados()."""

    def test_listar_bloqueados_arquivo_inexistente(self, tmp_path, monkeypatch):
        """Retorna lista vazia quando o arquivo não existe."""
        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "nao_existe.conf",
        )
        fw = FirewallManager()
        assert fw.listar_bloqueados() == []

    def test_listar_bloqueados_reflete_estado(self, tmp_path, monkeypatch):
        """listar_bloqueados() retorna os IPs presentes no arquivo."""
        arquivo = tmp_path / "blocked_ips.conf"
        arquivo.write_text("192.168.0.1\n10.0.0.2\n172.16.0.3\n")
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)

        fw = FirewallManager()
        bloqueados = fw.listar_bloqueados()

        assert "192.168.0.1" in bloqueados
        assert "10.0.0.2" in bloqueados
        assert "172.16.0.3" in bloqueados
        assert len(bloqueados) == 3

    def test_listar_bloqueados_apos_bloquear(self, tmp_path, monkeypatch):
        """IP aparece em listar_bloqueados() após bloquear_ip() bem-sucedido."""
        arquivo = tmp_path / "blocked_ips.conf"
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)
        mock_run = _make_subprocess_mock(returncode_check=1, returncode_action=0)
        monkeypatch.setattr("subprocess.run", mock_run)

        fw = FirewallManager()
        fw.bloquear_ip("203.0.113.1")

        assert "203.0.113.1" in fw.listar_bloqueados()

    def test_listar_bloqueados_apos_desbloquear(self, tmp_path, monkeypatch):
        """IP não aparece em listar_bloqueados() após desbloquear_ip() bem-sucedido."""
        arquivo = tmp_path / "blocked_ips.conf"
        arquivo.write_text("203.0.113.2\n")
        monkeypatch.setattr("response.firewall._ARQUIVO_BLOQUEADOS", arquivo)

        resultado = MagicMock()
        resultado.returncode = 0
        resultado.stdout = ""
        resultado.stderr = ""
        monkeypatch.setattr("subprocess.run", MagicMock(return_value=resultado))

        fw = FirewallManager()
        fw.desbloquear_ip("203.0.113.2")

        assert "203.0.113.2" not in fw.listar_bloqueados()


class TestTimestamp:
    """Testes para garantir que o timestamp está em ISO 8601 UTC."""

    def test_timestamp_iso8601_utc(self, tmp_path, monkeypatch):
        """ResponseAction retornado tem timestamp em formato ISO 8601 UTC."""
        from datetime import datetime, timezone

        monkeypatch.setattr(
            "response.firewall._ARQUIVO_BLOQUEADOS",
            tmp_path / "blocked_ips.conf",
        )
        mock_run = _make_subprocess_mock(returncode_check=1, returncode_action=0)
        monkeypatch.setattr("subprocess.run", mock_run)

        fw = FirewallManager()
        acao = fw.bloquear_ip("1.1.1.1")

        # Deve ser parseável como ISO 8601
        ts = acao.timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None


# =============================================================
# Property-Based Tests — 8.3 a 8.6
# =============================================================

class TestPropriedades:
    """
    Testes de propriedade para FirewallManager.

    Usa tempfile.TemporaryDirectory internamente (em vez de fixture tmp_path)
    para compatibilidade com Hypothesis, que não reseta fixtures entre exemplos.

    **Validates: Requirements 7.2, 7.3, 7.4, 7.5, 7.6**
    """

    @given(ip=_ip_valido())
    @settings(max_examples=30)
    def test_property_14_bloquear_ip_idempotente(self, ip):
        """
        Property 14: FirewallManager.bloquear_ip() é idempotente.

        Para qualquer IPv4 válido, duas chamadas consecutivas a bloquear_ip()
        retornam status="success" sem criar regras duplicadas.

        **Validates: Requirements 7.2**
        """
        import tempfile
        import response.firewall as fw_module

        with tempfile.TemporaryDirectory() as tmpdir:
            arquivo = Path(tmpdir) / "blocked_ips.conf"
            chamadas_acao = {"count": 0}

            def side_effect(cmd, **kwargs):
                resultado = MagicMock()
                resultado.stdout = ""
                resultado.stderr = ""
                if "-C" in cmd:
                    resultado.returncode = 1 if chamadas_acao["count"] == 0 else 0
                else:
                    resultado.returncode = 0
                    chamadas_acao["count"] += 1
                return resultado

            original_arquivo = fw_module._ARQUIVO_BLOQUEADOS
            fw_module._ARQUIVO_BLOQUEADOS = arquivo
            try:
                with patch("subprocess.run", side_effect=side_effect):
                    fw = FirewallManager()
                    acao1 = fw.bloquear_ip(ip)
                    acao2 = fw.bloquear_ip(ip)

                assert acao1.status == "success"
                assert acao2.status == "success"
                assert chamadas_acao["count"] == 1
            finally:
                fw_module._ARQUIVO_BLOQUEADOS = original_arquivo

    @given(ip=_ip_valido())
    @settings(max_examples=30)
    def test_property_15_persiste_ips_bloqueados(self, ip):
        """
        Property 15: FirewallManager persiste IPs bloqueados.

        Para qualquer IPv4 válido, após bloquear_ip() bem-sucedido,
        o IP aparece em listar_bloqueados().

        **Validates: Requirements 7.3, 7.5**
        """
        import tempfile
        import response.firewall as fw_module

        with tempfile.TemporaryDirectory() as tmpdir:
            arquivo = Path(tmpdir) / "blocked_ips.conf"
            original_arquivo = fw_module._ARQUIVO_BLOQUEADOS
            fw_module._ARQUIVO_BLOQUEADOS = arquivo
            try:
                mock_run = _make_subprocess_mock(returncode_check=1, returncode_action=0)
                with patch("subprocess.run", mock_run):
                    fw = FirewallManager()
                    acao = fw.bloquear_ip(ip)

                assert acao.status == "success"
                assert ip in fw.listar_bloqueados()
            finally:
                fw_module._ARQUIVO_BLOQUEADOS = original_arquivo

    @given(ip=_ip_valido())
    @settings(max_examples=30)
    def test_property_16_block_unblock_round_trip(self, ip):
        """
        Property 16: FirewallManager block/unblock é round-trip.

        Para qualquer IPv4 válido, após bloquear_ip() seguido de desbloquear_ip(),
        o IP não aparece em listar_bloqueados().

        **Validates: Requirements 7.4**
        """
        import tempfile
        import response.firewall as fw_module

        with tempfile.TemporaryDirectory() as tmpdir:
            arquivo = Path(tmpdir) / "blocked_ips.conf"
            original_arquivo = fw_module._ARQUIVO_BLOQUEADOS
            fw_module._ARQUIVO_BLOQUEADOS = arquivo
            try:
                resultado_ok = MagicMock()
                resultado_ok.returncode = 0
                resultado_ok.stdout = ""
                resultado_ok.stderr = ""

                chamadas_acao = {"count": 0}

                def side_effect_bloquear(cmd, **kwargs):
                    if "-C" in cmd:
                        r = MagicMock()
                        r.stdout = ""
                        r.stderr = ""
                        r.returncode = 1 if chamadas_acao["count"] == 0 else 0
                        return r
                    chamadas_acao["count"] += 1
                    return resultado_ok

                fw = FirewallManager()
                with patch("subprocess.run", side_effect=side_effect_bloquear):
                    fw.bloquear_ip(ip)

                with patch("subprocess.run", return_value=resultado_ok):
                    fw.desbloquear_ip(ip)

                assert ip not in fw.listar_bloqueados()
            finally:
                fw_module._ARQUIVO_BLOQUEADOS = original_arquivo

    @given(ip=_ip_valido())
    @settings(max_examples=30)
    def test_property_17_resiliente_falha_permissao(self, ip):
        """
        Property 17: FirewallManager é resiliente a falhas de permissão.

        Para qualquer IPv4 válido com subprocess falhando por permissão,
        bloquear_ip() retorna status="failed" sem lançar exceção.

        **Validates: Requirements 7.6**
        """
        import tempfile
        import response.firewall as fw_module

        with tempfile.TemporaryDirectory() as tmpdir:
            arquivo = Path(tmpdir) / "blocked_ips.conf"
            original_arquivo = fw_module._ARQUIVO_BLOQUEADOS
            fw_module._ARQUIVO_BLOQUEADOS = arquivo
            try:
                resultado_falha = MagicMock()
                resultado_falha.returncode = 1
                resultado_falha.stdout = ""
                resultado_falha.stderr = "iptables: Operation not permitted"

                with patch("subprocess.run", return_value=resultado_falha):
                    fw = FirewallManager()
                    acao = fw.bloquear_ip(ip)

                assert acao.status == "failed"
                assert acao.erro is not None
            finally:
                fw_module._ARQUIVO_BLOQUEADOS = original_arquivo
