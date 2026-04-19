"""
Cellular / IP Security Advisor
===============================
A rule-based expert-system module that evaluates a cellular-IP configuration
profile and produces prioritised security findings together with actionable
recommendations.

The advisor deliberately operates on *configuration data* (dictionaries) rather
than talking directly to the OS so that it can be tested portably and extended
without platform coupling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Individual rule functions
# Each rule receives the full profile dict and returns a Finding or None.
# ---------------------------------------------------------------------------


def _rule_vpn_required(profile: dict[str, Any]) -> Finding | None:
    """C-001: A VPN must be active whenever the device is on a cellular network."""
    if not profile.get("vpn_active", False):
        return Finding(
            rule_id="C-001",
            severity=Severity.CRITICAL,
            title="VPN not active on cellular connection",
            description=(
                "Without a VPN, IP traffic is transmitted in the clear to the carrier "
                "and can be intercepted by rogue base stations (IMSI catchers / Stingrays)."
            ),
            recommendation=(
                "Enable a trusted VPN (WireGuard or OpenVPN with AES-256-GCM) before "
                "connecting to any cellular network. Configure the VPN to use a "
                "kill-switch so traffic is blocked if the VPN drops."
            ),
        )
    return None


def _rule_vpn_protocol_strength(profile: dict[str, Any]) -> Finding | None:
    """C-002: VPN protocol must be WireGuard or OpenVPN; PPTP and L2TP are insecure."""
    if not profile.get("vpn_active", False):
        return None  # C-001 already fired
    weak_protocols = {"pptp", "l2tp", "l2tp/ipsec-psk"}
    vpn_protocol = profile.get("vpn_protocol", "").lower()
    if vpn_protocol in weak_protocols:
        return Finding(
            rule_id="C-002",
            severity=Severity.CRITICAL,
            title=f"Insecure VPN protocol in use: {vpn_protocol.upper()}",
            description=(
                f"The protocol '{vpn_protocol}' has known cryptographic weaknesses. "
                "PPTP is completely broken; L2TP/IPSec with a pre-shared key is "
                "vulnerable to offline dictionary attacks."
            ),
            recommendation=(
                "Switch to WireGuard (preferred) or OpenVPN with TLS 1.3 / "
                "AES-256-GCM. Both are open-source, audited, and widely supported."
            ),
        )
    return None


def _rule_network_generation(profile: dict[str, Any]) -> Finding | None:
    """C-003: 2G/GPRS networks offer weak encryption; advise upgrade."""
    generation = str(profile.get("network_generation", "")).strip().upper()
    if generation in {"2G", "GPRS", "EDGE"}:
        return Finding(
            rule_id="C-003",
            severity=Severity.HIGH,
            title=f"Weak cellular generation in use: {generation}",
            description=(
                "2G/GPRS networks use A5/1 stream cipher which has been publicly "
                "broken. Attackers with commodity SDR hardware can passively decrypt "
                "traffic and perform active man-in-the-middle attacks."
            ),
            recommendation=(
                "Disable 2G fallback in your device's network settings and force "
                "4G LTE or 5G NR minimum. Most carriers offer this via "
                "'Preferred network type' in Settings → Mobile network."
            ),
        )
    return None


def _rule_roaming_security(profile: dict[str, Any]) -> Finding | None:
    """C-004: Data roaming over foreign carriers increases interception risk."""
    if profile.get("data_roaming_enabled", False) and not profile.get("vpn_active", False):
        return Finding(
            rule_id="C-004",
            severity=Severity.HIGH,
            title="Data roaming active without VPN protection",
            description=(
                "While roaming, traffic is handled by a foreign carrier whose security "
                "posture may be unknown. Combined with the absence of a VPN, all IP "
                "traffic is exposed."
            ),
            recommendation=(
                "Always activate your VPN before enabling data roaming, or disable "
                "data roaming entirely and use Wi-Fi with a trusted VPN instead."
            ),
        )
    return None


def _rule_dns_over_https(profile: dict[str, Any]) -> Finding | None:
    """C-005: Plain DNS leaks queries to carrier and enables DNS spoofing."""
    if not profile.get("dns_over_https_enabled", False):
        return Finding(
            rule_id="C-005",
            severity=Severity.MEDIUM,
            title="DNS-over-HTTPS (DoH) not enabled",
            description=(
                "Plain DNS (UDP/53) queries are sent in the clear, revealing visited "
                "hostnames to the carrier and any on-path observer. Attackers can "
                "also spoof DNS responses (DNS cache poisoning)."
            ),
            recommendation=(
                "Enable DNS-over-HTTPS using a privacy-respecting resolver such as "
                "Cloudflare (1.1.1.1) or NextDNS. On Android 9+: Settings → "
                "Network → Private DNS → enter your DoH hostname."
            ),
        )
    return None


def _rule_imei_randomisation(profile: dict[str, Any]) -> Finding | None:
    """C-006: Static IMEI/IMSI allows tracking across sessions."""
    if not profile.get("imei_privacy_mode", False):
        return Finding(
            rule_id="C-006",
            severity=Severity.LOW,
            title="IMEI / IMSI privacy mode not enabled",
            description=(
                "A fixed IMEI/IMSI allows carriers, law enforcement, and IMSI catchers "
                "to correlate activity across time even when the SIM card changes."
            ),
            recommendation=(
                "Use a carrier or OS that supports IMSI randomisation (5G SUPI "
                "concealment or GrapheneOS randomised IMEI). Alternatively, combine "
                "with a VPN and rotate SIM cards when high anonymity is required."
            ),
        )
    return None


def _rule_apn_tls(profile: dict[str, Any]) -> Finding | None:
    """C-007: APN connection to carrier backend must be TLS-protected."""
    apn_tls = profile.get("apn_uses_tls", True)  # default-safe: assume TLS unless told otherwise
    if apn_tls is False:
        return Finding(
            rule_id="C-007",
            severity=Severity.MEDIUM,
            title="APN carrier backend connection does not use TLS",
            description=(
                "Some MVNOs and enterprise APNs still communicate with backend servers "
                "over unencrypted HTTP. This exposes session metadata and potentially "
                "control-plane messages."
            ),
            recommendation=(
                "Contact your carrier to verify TLS is enforced on the APN endpoint. "
                "If configuring a custom APN, set the APN type to 'default,supl' and "
                "ensure the MMS proxy (if any) uses HTTPS."
            ),
        )
    return None


def _rule_firewall_enabled(profile: dict[str, Any]) -> Finding | None:
    """C-008: A host-based firewall reduces attack surface on the device."""
    if not profile.get("firewall_enabled", False):
        return Finding(
            rule_id="C-008",
            severity=Severity.MEDIUM,
            title="Host-based firewall not enabled",
            description=(
                "Without a firewall, any app granted internet permission can make "
                "arbitrary outbound connections and receive unsolicited inbound packets."
            ),
            recommendation=(
                "Enable a host-based firewall such as AFWall+ (root), NetGuard "
                "(no-root), or the built-in Private DNS + per-app network permission "
                "controls available on Android 10+."
            ),
        )
    return None


# Registry of all cellular rules (order determines evaluation sequence)
_CELLULAR_RULES = [
    _rule_vpn_required,
    _rule_vpn_protocol_strength,
    _rule_network_generation,
    _rule_roaming_security,
    _rule_dns_over_https,
    _rule_imei_randomisation,
    _rule_apn_tls,
    _rule_firewall_enabled,
]

# Severity ordering for sorting (lower index = higher priority)
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class CellularSecurityReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """
        Simple security score 0-100.

        Starts at 100 and deducts points per finding:
          CRITICAL → -25, HIGH → -15, MEDIUM → -8, LOW → -3, INFO → 0
        """
        deductions = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        total = 100 - sum(deductions.get(f.severity, 0) for f in self.findings)
        return max(0, total)

    def is_secure(self) -> bool:
        """Returns True only when there are no CRITICAL or HIGH findings."""
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def summary(self) -> str:
        lines = [
            "=== Cellular / IP Security Report ===",
            f"Security score : {self.score}/100",
            f"Status         : {'SECURE ✓' if self.is_secure() else 'INSECURE ✗'}",
            f"Total findings : {len(self.findings)}",
            "",
        ]
        if not self.findings:
            lines.append("No security issues detected.")
        else:
            for f in self.findings:
                lines += [
                    f"[{f.severity.value}] {f.rule_id} – {f.title}",
                    f"  Description    : {f.description}",
                    f"  Recommendation : {f.recommendation}",
                    "",
                ]
        return "\n".join(lines)


class CellularSecurityAdvisor:
    """
    Evaluates a cellular/IP configuration profile against a set of security
    rules and returns a :class:`CellularSecurityReport`.

    Parameters
    ----------
    profile:
        A dict describing the current cellular configuration.  Recognised keys:

        - ``vpn_active`` (bool)        – Is a VPN currently connected?
        - ``vpn_protocol`` (str)       – e.g. ``"wireguard"``, ``"openvpn"``, ``"pptp"``
        - ``network_generation`` (str) – e.g. ``"5G"``, ``"4G"``, ``"2G"``
        - ``data_roaming_enabled`` (bool)
        - ``dns_over_https_enabled`` (bool)
        - ``imei_privacy_mode`` (bool)
        - ``apn_uses_tls`` (bool)
        - ``firewall_enabled`` (bool)
    """

    def __init__(self, profile: dict[str, Any]) -> None:
        if not isinstance(profile, dict):
            raise TypeError("profile must be a dict")
        self._profile = profile

    def evaluate(self) -> CellularSecurityReport:
        """Run all rules and return the consolidated report."""
        findings: list[Finding] = []
        for rule in _CELLULAR_RULES:
            result = rule(self._profile)
            if result is not None:
                findings.append(result)
        # Sort by severity
        findings.sort(key=lambda f: _SEVERITY_ORDER[f.severity])
        return CellularSecurityReport(findings=findings)
