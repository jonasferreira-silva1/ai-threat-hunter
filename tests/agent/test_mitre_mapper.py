"""
Testes para MITREMapper — AI-Powered Threat Hunter
===================================================
Cobre os requisitos 4.1 a 4.7:
    - Cada uma das 6 classes conhecidas retorna a técnica ATT&CK correta
    - Classes desconhecidas retornam lista vazia sem lançar exceção

Inclui testes unitários (task 2.2) e property-based tests (task 2.3).
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent.mitre_mapper import MITREMapper


# =============================================================
# Fixtures
# =============================================================

@pytest.fixture
def mapper():
    """Instância de MITREMapper para uso nos testes."""
    return MITREMapper()


# =============================================================
# Testes unitários — task 2.2
# =============================================================

class TestMITREMapperClassesConhecidas:
    """Valida que cada classe conhecida retorna a técnica ATT&CK correta."""

    @pytest.mark.unit
    def test_brute_force_retorna_t1110(self, mapper):
        """Requisito 4.1: BRUTE_FORCE → T1110."""
        resultado = mapper.mapear("BRUTE_FORCE")
        assert "T1110" in resultado

    @pytest.mark.unit
    def test_port_scan_retorna_t1046(self, mapper):
        """Requisito 4.2: PORT_SCAN → T1046."""
        resultado = mapper.mapear("PORT_SCAN")
        assert "T1046" in resultado

    @pytest.mark.unit
    def test_data_exfiltration_retorna_t1041(self, mapper):
        """Requisito 4.3: DATA_EXFILTRATION → T1041."""
        resultado = mapper.mapear("DATA_EXFILTRATION")
        assert "T1041" in resultado

    @pytest.mark.unit
    def test_privilege_escalation_retorna_t1068(self, mapper):
        """Requisito 4.4: PRIVILEGE_ESCALATION → T1068."""
        resultado = mapper.mapear("PRIVILEGE_ESCALATION")
        assert "T1068" in resultado

    @pytest.mark.unit
    def test_lateral_movement_retorna_t1021(self, mapper):
        """Requisito 4.5: LATERAL_MOVEMENT → T1021."""
        resultado = mapper.mapear("LATERAL_MOVEMENT")
        assert "T1021" in resultado

    @pytest.mark.unit
    def test_ddos_retorna_t1498(self, mapper):
        """Requisito 4.6: DDOS → T1498."""
        resultado = mapper.mapear("DDOS")
        assert "T1498" in resultado

    @pytest.mark.unit
    def test_todas_as_classes_retornam_lista(self, mapper):
        """Todas as classes conhecidas retornam list[str] não-vazia."""
        for classe in MITREMapper.MAPEAMENTO:
            resultado = mapper.mapear(classe)
            assert isinstance(resultado, list)
            assert len(resultado) > 0

    @pytest.mark.unit
    def test_mapear_com_contexto_none(self, mapper):
        """Contexto None não causa erro — parâmetro é opcional."""
        resultado = mapper.mapear("BRUTE_FORCE", contexto=None)
        assert "T1110" in resultado


class TestMITREMapperClassesDesconhecidas:
    """Valida que classes desconhecidas retornam lista vazia sem exceção."""

    @pytest.mark.unit
    def test_classe_desconhecida_retorna_lista_vazia(self, mapper):
        """Requisito 4.7: classe desconhecida → []."""
        resultado = mapper.mapear("CLASSE_INEXISTENTE")
        assert resultado == []

    @pytest.mark.unit
    def test_string_vazia_retorna_lista_vazia(self, mapper):
        """String vazia não lança exceção e retorna []."""
        resultado = mapper.mapear("")
        assert resultado == []

    @pytest.mark.unit
    def test_classe_minuscula_retorna_lista_vazia(self, mapper):
        """Mapeamento é case-sensitive; 'brute_force' não é reconhecido."""
        resultado = mapper.mapear("brute_force")
        assert resultado == []

    @pytest.mark.unit
    def test_normal_retorna_lista_vazia(self, mapper):
        """Classe NORMAL (sem ameaça) não tem técnica ATT&CK mapeada."""
        resultado = mapper.mapear("NORMAL")
        assert resultado == []

    @pytest.mark.unit
    def test_retorno_e_copia_independente(self, mapper):
        """Modificar o retorno não altera o MAPEAMENTO interno."""
        resultado = mapper.mapear("BRUTE_FORCE")
        resultado.append("T9999")
        assert "T9999" not in mapper.MAPEAMENTO["BRUTE_FORCE"]


# =============================================================
# Property-based test — task 2.3
# **Validates: Requirements 4.7**
# =============================================================

# Conjunto de classes conhecidas para excluir do gerador
_CLASSES_CONHECIDAS = set(MITREMapper.MAPEAMENTO.keys())


@given(
    classe=st.text().filter(lambda s: s not in _CLASSES_CONHECIDAS)
)
@settings(max_examples=200)
def test_property_classes_desconhecidas_retornam_lista_vazia(classe):
    """
    **Validates: Requirements 4.7**

    Property 8: MITREMapper retorna lista vazia para classes desconhecidas.

    Para qualquer string fora do conjunto de classes conhecidas,
    `mapear()` deve retornar `[]` sem lançar exceção.
    """
    mapper = MITREMapper()
    resultado = mapper.mapear(classe)
    assert resultado == [], (
        f"Esperado [] para classe desconhecida '{classe}', obtido {resultado}"
    )
