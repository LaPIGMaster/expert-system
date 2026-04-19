"""
Bluetooth Security Advisor
===========================
A rule-based expert-system module that evaluates a Bluetooth configuration
profile and produces prioritised security findings together with actionable
recommendations.

Like the cellular advisor, this module operates on *configuration data*
(dictionaries) so it can be tested portably across platforms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .cellular import Finding, Severity, _SEVERITY_ORDER  # re-use shared types


# ---------------------------------------------------------------------------
# Individual rule functions
# ---------------------------------------------------------------------------


def _rule_discoverability(profile: dict[str, Any]) -> Finding | None:
    """B-001: Device must not be permanently discoverable."""
    if profile.get("always_discoverable", False):
        return Finding(
            rule_id="B-001",
            severity=Severity.HIGH,
            title="Bluetooth device is always discoverable",
            description=(
                "A permanently discoverable device broadcasts its presence to all "
                "nearby scanners, enabling passive tracking and opportunistic pairing "
                "attacks (BlueBorne, KNOB)."
            ),
            recommendation=(
                "Set discoverability to 'temporary' (e.g. 2 minutes) only when "
                "actively pairing a new device. After pairing, turn discoverability "
                "off. Most modern OS defaults do this automatically."
            ),
        )
    return None


def _rule_secure_simple_pairing(profile: dict[str, Any]) -> Finding | None:
    """B-002: Secure Simple Pairing (SSP) / LE Secure Connections must be enabled."""
    if not profile.get("secure_simple_pairing", True):
        return Finding(
            rule_id="B-002",
            severity=Severity.CRITICAL,
            title="Secure Simple Pairing (SSP) is disabled",
            description=(
                "Without SSP / LE Secure Connections, the pairing process uses "
                "legacy PIN-based authentication which is vulnerable to brute-force "
                "and passive eavesdropping attacks."
            ),
            recommendation=(
                "Enable Bluetooth Secure Simple Pairing (Bluetooth 2.1+) or "
                "LE Secure Connections (Bluetooth 4.2+). Both use ECDH key exchange "
                "to prevent eavesdropping and MITM attacks."
            ),
        )
    return None


def _rule_encryption_enabled(profile: dict[str, Any]) -> Finding | None:
    """B-003: Link-layer encryption must be active on established connections."""
    if not profile.get("link_encryption_enabled", True):
        return Finding(
            rule_id="B-003",
            severity=Severity.CRITICAL,
            title="Bluetooth link-layer encryption is disabled",
            description=(
                "Disabling link encryption means all transmitted data (audio, HID "
                "keystrokes, file transfers) is sent in the clear and can be captured "
                "with a commodity Bluetooth sniffer."
            ),
            recommendation=(
                "Ensure link-layer encryption is always active. This is controlled by "
                "the OS Bluetooth stack; updating to the latest firmware/OS patch is "
                "typically sufficient. Never disable it via developer/debug options."
            ),
        )
    return None


def _rule_bluetooth_version(profile: dict[str, Any]) -> Finding | None:
    """B-004: Old Bluetooth versions have known protocol-level vulnerabilities."""
    try:
        version = float(profile.get("bluetooth_version", 5.0))
    except (TypeError, ValueError):
        return None
    if version < 4.2:
        return Finding(
            rule_id="B-004",
            severity=Severity.HIGH,
            title=f"Outdated Bluetooth version: {version}",
            description=(
                f"Bluetooth {version} pre-dates LE Secure Connections (4.2) and is "
                "missing several mandatory security improvements. Known attacks "
                "include KNOB (Key Negotiation of Bluetooth) and BIAS "
                "(Bluetooth Impersonation AttackS)."
            ),
            recommendation=(
                "Update device firmware to support Bluetooth 5.0+ where possible. "
                "If the device cannot be updated, restrict its use to trusted "
                "environments and avoid transmitting sensitive data."
            ),
        )
    return None


def _rule_paired_device_allowlist(profile: dict[str, Any]) -> Finding | None:
    """B-005: Unknown or excessive paired devices increase the attack surface."""
    paired = profile.get("paired_devices", [])
    if not isinstance(paired, list):
        return None
    unknown = [d for d in paired if not d.get("trusted", True)]
    if unknown:
        names = ", ".join(d.get("name", "unknown") for d in unknown[:5])
        return Finding(
            rule_id="B-005",
            severity=Severity.MEDIUM,
            title=f"Untrusted paired device(s) found: {names}",
            description=(
                "Paired devices that are no longer in use or are marked as untrusted "
                "retain cryptographic keys that could be replayed by an attacker who "
                "clones or intercepts the peripheral."
            ),
            recommendation=(
                "Remove all unused or unrecognised paired devices immediately. "
                "Audit your paired device list regularly and keep only actively "
                "used peripherals."
            ),
        )
    return None


def _rule_bluetooth_disabled_when_unused(profile: dict[str, Any]) -> Finding | None:
    """B-006: Bluetooth should be off when not in use."""
    if not profile.get("bluetooth_enabled", True):
        return None  # already off – no finding
    if not profile.get("active_connection", False) and not profile.get("expected_active", True):
        return Finding(
            rule_id="B-006",
            severity=Severity.LOW,
            title="Bluetooth enabled with no active connections",
            description=(
                "Leaving Bluetooth on when not in use increases the passive attack "
                "surface (scanning fingerprinting, zero-click exploits targeting "
                "the Bluetooth stack)."
            ),
            recommendation=(
                "Disable Bluetooth when you are not actively using a peripheral. "
                "Use quick-settings toggles or automation apps (e.g. Tasker) to "
                "turn Bluetooth off automatically after a period of inactivity."
            ),
        )
    return None


def _rule_ble_privacy(profile: dict[str, Any]) -> Finding | None:
    """B-007: BLE devices must use resolvable private addresses to prevent tracking."""
    if profile.get("ble_address_type", "random").lower() == "public":
        return Finding(
            rule_id="B-007",
            severity=Severity.MEDIUM,
            title="BLE using public (static) MAC address",
            description=(
                "A static public BLE MAC address allows passive observers to track "
                "device movement over time even without pairing. This is a privacy "
                "and security risk in hostile RF environments."
            ),
            recommendation=(
                "Enable Bluetooth LE Privacy / Resolvable Private Addresses (RPA) "
                "in your OS Bluetooth settings. iOS, Android 8+, and Windows 10+ "
                "all support RPA by default for most BLE roles."
            ),
        )
    return None


def _rule_no_open_profiles(profile: dict[str, Any]) -> Finding | None:
    """B-008: High-risk Bluetooth profiles should be disabled when unused."""
    risky_profiles = {"obex", "opp", "pan", "bnep"}
    enabled_profiles = {p.lower() for p in profile.get("enabled_profiles", [])}
    active = risky_profiles & enabled_profiles
    if active:
        return Finding(
            rule_id="B-008",
            severity=Severity.MEDIUM,
            title=f"High-risk Bluetooth profile(s) enabled: {', '.join(sorted(active)).upper()}",
            description=(
                "Profiles such as OBEX Push (OPP), Personal Area Network (PAN/BNEP) "
                "have historically contained exploitable vulnerabilities and expand "
                "the Bluetooth attack surface unnecessarily."
            ),
            recommendation=(
                "Disable Bluetooth profiles that are not actively required. On Android "
                "you can manage profiles per device; on desktop OSes use the Bluetooth "
                "adapter settings to restrict available services."
            ),
        )
    return None


# Registry of all Bluetooth rules
_BLUETOOTH_RULES = [
    _rule_discoverability,
    _rule_secure_simple_pairing,
    _rule_encryption_enabled,
    _rule_bluetooth_version,
    _rule_paired_device_allowlist,
    _rule_bluetooth_disabled_when_unused,
    _rule_ble_privacy,
    _rule_no_open_profiles,
]


@dataclass
class BluetoothSecurityReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Security score 0-100 (same deduction scheme as CellularSecurityReport)."""
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
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def summary(self) -> str:
        lines = [
            "=== Bluetooth Security Report ===",
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


class BluetoothSecurityAdvisor:
    """
    Evaluates a Bluetooth configuration profile against a set of security
    rules and returns a :class:`BluetoothSecurityReport`.

    Parameters
    ----------
    profile:
        A dict describing the current Bluetooth configuration.  Recognised keys:

        - ``always_discoverable`` (bool)     – Is the device permanently discoverable?
        - ``secure_simple_pairing`` (bool)   – Is SSP / LE Secure Connections enabled?
        - ``link_encryption_enabled`` (bool) – Is link-layer encryption enforced?
        - ``bluetooth_version`` (float)      – e.g. ``5.3``
        - ``paired_devices`` (list[dict])    – Each entry may have ``name`` and ``trusted`` keys.
        - ``bluetooth_enabled`` (bool)       – Is Bluetooth switched on?
        - ``active_connection`` (bool)       – Is there a current active connection?
        - ``expected_active`` (bool)         – Is Bluetooth expected to be in use right now?
        - ``ble_address_type`` (str)         – ``"public"`` or ``"random"``
        - ``enabled_profiles`` (list[str])   – e.g. ``["A2DP", "HFP", "OPP"]``
    """

    def __init__(self, profile: dict[str, Any]) -> None:
        if not isinstance(profile, dict):
            raise TypeError("profile must be a dict")
        self._profile = profile

    def evaluate(self) -> BluetoothSecurityReport:
        """Run all rules and return the consolidated report."""
        findings: list[Finding] = []
        for rule in _BLUETOOTH_RULES:
            result = rule(self._profile)
            if result is not None:
                findings.append(result)
        findings.sort(key=lambda f: _SEVERITY_ORDER[f.severity])
        return BluetoothSecurityReport(findings=findings)
