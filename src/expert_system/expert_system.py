"""
Expert System Orchestrator
===========================
Combines the CellularSecurityAdvisor and BluetoothSecurityAdvisor into a
single evaluation pass and produces a consolidated security report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .advisors.bluetooth import BluetoothSecurityAdvisor, BluetoothSecurityReport
from .advisors.cellular import CellularSecurityAdvisor, CellularSecurityReport


@dataclass
class ConsolidatedReport:
    cellular: CellularSecurityReport
    bluetooth: BluetoothSecurityReport

    @property
    def overall_score(self) -> int:
        """Average of both subsystem scores."""
        return (self.cellular.score + self.bluetooth.score) // 2

    def is_secure(self) -> bool:
        return self.cellular.is_secure() and self.bluetooth.is_secure()

    def summary(self) -> str:
        divider = "=" * 50
        lines = [
            divider,
            "  EXPERT SYSTEM – DEVICE SECURITY ASSESSMENT",
            divider,
            "",
            self.cellular.summary(),
            "",
            self.bluetooth.summary(),
            "",
            divider,
            f"  OVERALL SCORE  : {self.overall_score}/100",
            f"  OVERALL STATUS : {'SECURE ✓' if self.is_secure() else 'INSECURE – ACTION REQUIRED ✗'}",
            divider,
        ]
        return "\n".join(lines)


class ExpertSystem:
    """
    Top-level orchestrator.

    Parameters
    ----------
    cellular_profile:
        Configuration dict passed to :class:`~advisors.cellular.CellularSecurityAdvisor`.
    bluetooth_profile:
        Configuration dict passed to :class:`~advisors.bluetooth.BluetoothSecurityAdvisor`.
    """

    def __init__(
        self,
        cellular_profile: dict[str, Any],
        bluetooth_profile: dict[str, Any],
    ) -> None:
        self._cellular_advisor = CellularSecurityAdvisor(cellular_profile)
        self._bluetooth_advisor = BluetoothSecurityAdvisor(bluetooth_profile)

    def run(self) -> ConsolidatedReport:
        """Evaluate both advisors and return a :class:`ConsolidatedReport`."""
        return ConsolidatedReport(
            cellular=self._cellular_advisor.evaluate(),
            bluetooth=self._bluetooth_advisor.evaluate(),
        )
