"""
MITREMapper — AI-Powered Threat Hunter
=======================================
Responsabilidade:
    Mapear classes de ameaça detectadas pelo pipeline de ML para técnicas
    e táticas do framework MITRE ATT&CK, fornecendo contexto padronizado
    para investigação e relatórios de incidente.

Referência: https://attack.mitre.org/
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dataclasses import dataclass

logger = logging.getLogger("threat-hunter.agent.mitre_mapper")


class MITREMapper:
    """
    Mapeia classes de ameaça para técnicas e táticas do MITRE ATT&CK.

    Uso:
        mapper = MITREMapper()
        tecnicas = mapper.mapear("BRUTE_FORCE", contexto)
        # → ["T1110"]
    """

    # ----------------------------------------------------------
    # Mapeamento: classe de ameaça → técnicas ATT&CK
    # ----------------------------------------------------------

    MAPEAMENTO: dict[str, list[str]] = {
        "BRUTE_FORCE":          ["T1110"],   # Brute Force (TA0006 - Credential Access)
        "PORT_SCAN":            ["T1046"],   # Network Service Discovery (TA0007 - Discovery)
        "DDOS":                 ["T1498"],   # Network Denial of Service (TA0040 - Impact)
        "LATERAL_MOVEMENT":     ["T1021"],   # Remote Services (TA0008 - Lateral Movement)
        "DATA_EXFILTRATION":    ["T1041"],   # Exfiltration Over C2 Channel (TA0010 - Exfiltration)
        "PRIVILEGE_ESCALATION": ["T1068"],   # Exploitation for Privilege Escalation (TA0004)
    }

    # Táticas ATT&CK associadas a cada técnica
    TATICAS: dict[str, str] = {
        "T1110": "TA0006",  # Credential Access
        "T1046": "TA0007",  # Discovery
        "T1498": "TA0040",  # Impact
        "T1021": "TA0008",  # Lateral Movement
        "T1041": "TA0010",  # Exfiltration
        "T1068": "TA0004",  # Privilege Escalation
    }

    def mapear(self, classe_ameaca: str, contexto: object = None) -> list[str]:
        """
        Retorna as técnicas ATT&CK associadas à classe de ameaça informada.

        Args:
            classe_ameaca: Nome da classe de ameaça (ex: "BRUTE_FORCE").
                           Deve corresponder a uma das chaves de ``MAPEAMENTO``.
            contexto:      ThreatContext opcional para enriquecimento futuro.
                           Atualmente não utilizado — reservado para extensões.

        Returns:
            Lista de identificadores de técnicas ATT&CK (ex: ["T1110"]).
            Retorna lista vazia para classes desconhecidas, sem lançar exceção.
        """
        tecnicas = self.MAPEAMENTO.get(classe_ameaca, [])

        if not tecnicas:
            logger.debug(
                "Classe de ameaça desconhecida para mapeamento MITRE: '%s'",
                classe_ameaca,
            )
        else:
            logger.debug(
                "Classe '%s' mapeada para técnicas ATT&CK: %s",
                classe_ameaca,
                tecnicas,
            )

        return list(tecnicas)

    def tatica(self, tecnica: str) -> str | None:
        """
        Retorna a tática ATT&CK associada a uma técnica.

        Args:
            tecnica: Identificador da técnica (ex: "T1110").

        Returns:
            Identificador da tática (ex: "TA0006") ou None se desconhecida.
        """
        return self.TATICAS.get(tecnica)
