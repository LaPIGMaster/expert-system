"""
Unit tests for the Cellular Security Advisor.
"""

import pytest

from src.expert_system.advisors.cellular import (
    CellularSecurityAdvisor,
    CellularSecurityReport,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECURE_PROFILE = {
    "vpn_active": True,
    "vpn_protocol": "wireguard",
    "network_generation": "5G",
    "data_roaming_enabled": False,
    "dns_over_https_enabled": True,
    "imei_privacy_mode": True,
    "apn_uses_tls": True,
    "firewall_enabled": True,
}


def _evaluate(overrides: dict) -> CellularSecurityReport:
    profile = {**SECURE_PROFILE, **overrides}
    return CellularSecurityAdvisor(profile).evaluate()


def _finding_ids(report: CellularSecurityReport) -> set[str]:
    return {f.rule_id for f in report.findings}


# ---------------------------------------------------------------------------
# Happy-path: fully secure configuration
# ---------------------------------------------------------------------------


class TestFullySecureProfile:
    def test_no_findings(self):
        report = _evaluate({})
        assert report.findings == []

    def test_score_is_100(self):
        report = _evaluate({})
        assert report.score == 100

    def test_is_secure(self):
        report = _evaluate({})
        assert report.is_secure() is True


# ---------------------------------------------------------------------------
# C-001: VPN required
# ---------------------------------------------------------------------------


class TestVpnRequired:
    def test_no_vpn_raises_c001(self):
        report = _evaluate({"vpn_active": False, "vpn_protocol": ""})
        assert "C-001" in _finding_ids(report)

    def test_c001_is_critical(self):
        report = _evaluate({"vpn_active": False, "vpn_protocol": ""})
        finding = next(f for f in report.findings if f.rule_id == "C-001")
        assert finding.severity == Severity.CRITICAL

    def test_vpn_on_clears_c001(self):
        report = _evaluate({"vpn_active": True})
        assert "C-001" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-002: VPN protocol strength
# ---------------------------------------------------------------------------


class TestVpnProtocol:
    @pytest.mark.parametrize("proto", ["pptp", "PPTP", "l2tp", "L2TP/IPSec-PSK"])
    def test_weak_protocol_raises_c002(self, proto):
        report = _evaluate({"vpn_active": True, "vpn_protocol": proto})
        assert "C-002" in _finding_ids(report)

    @pytest.mark.parametrize("proto", ["wireguard", "openvpn", "ikev2"])
    def test_strong_protocol_clears_c002(self, proto):
        report = _evaluate({"vpn_active": True, "vpn_protocol": proto})
        assert "C-002" not in _finding_ids(report)

    def test_c002_not_fired_when_vpn_off(self):
        # C-001 fires instead; C-002 should be suppressed
        report = _evaluate({"vpn_active": False, "vpn_protocol": "pptp"})
        assert "C-002" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-003: Network generation
# ---------------------------------------------------------------------------


class TestNetworkGeneration:
    @pytest.mark.parametrize("gen", ["2G", "GPRS", "EDGE", "gprs"])
    def test_weak_generation_raises_c003(self, gen):
        report = _evaluate({"network_generation": gen})
        assert "C-003" in _finding_ids(report)

    @pytest.mark.parametrize("gen", ["3G", "4G", "4G LTE", "5G"])
    def test_modern_generation_clears_c003(self, gen):
        report = _evaluate({"network_generation": gen})
        assert "C-003" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-004: Roaming without VPN
# ---------------------------------------------------------------------------


class TestRoaming:
    def test_roaming_without_vpn_raises_c004(self):
        report = _evaluate({"data_roaming_enabled": True, "vpn_active": False, "vpn_protocol": ""})
        assert "C-004" in _finding_ids(report)

    def test_roaming_with_vpn_clears_c004(self):
        report = _evaluate({"data_roaming_enabled": True, "vpn_active": True})
        assert "C-004" not in _finding_ids(report)

    def test_no_roaming_no_c004(self):
        report = _evaluate({"data_roaming_enabled": False, "vpn_active": False, "vpn_protocol": ""})
        assert "C-004" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-005: DNS-over-HTTPS
# ---------------------------------------------------------------------------


class TestDnsOverHttps:
    def test_no_doh_raises_c005(self):
        report = _evaluate({"dns_over_https_enabled": False})
        assert "C-005" in _finding_ids(report)

    def test_doh_enabled_clears_c005(self):
        report = _evaluate({"dns_over_https_enabled": True})
        assert "C-005" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-006: IMEI privacy
# ---------------------------------------------------------------------------


class TestImeiPrivacy:
    def test_no_imei_privacy_raises_c006(self):
        report = _evaluate({"imei_privacy_mode": False})
        assert "C-006" in _finding_ids(report)

    def test_imei_privacy_clears_c006(self):
        report = _evaluate({"imei_privacy_mode": True})
        assert "C-006" not in _finding_ids(report)

    def test_c006_is_low_severity(self):
        report = _evaluate({"imei_privacy_mode": False})
        finding = next(f for f in report.findings if f.rule_id == "C-006")
        assert finding.severity == Severity.LOW


# ---------------------------------------------------------------------------
# C-007: APN TLS
# ---------------------------------------------------------------------------


class TestApnTls:
    def test_no_apn_tls_raises_c007(self):
        report = _evaluate({"apn_uses_tls": False})
        assert "C-007" in _finding_ids(report)

    def test_apn_tls_clears_c007(self):
        report = _evaluate({"apn_uses_tls": True})
        assert "C-007" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# C-008: Firewall
# ---------------------------------------------------------------------------


class TestFirewall:
    def test_no_firewall_raises_c008(self):
        report = _evaluate({"firewall_enabled": False})
        assert "C-008" in _finding_ids(report)

    def test_firewall_enabled_clears_c008(self):
        report = _evaluate({"firewall_enabled": True})
        assert "C-008" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# Score / status helpers
# ---------------------------------------------------------------------------


class TestScoring:
    def test_score_decreases_with_findings(self):
        secure_score = _evaluate({}).score
        insecure_score = _evaluate({"vpn_active": False, "vpn_protocol": ""}).score
        assert insecure_score < secure_score

    def test_score_never_negative(self):
        # worst possible config
        worst = {
            "vpn_active": False,
            "vpn_protocol": "pptp",
            "network_generation": "2G",
            "data_roaming_enabled": True,
            "dns_over_https_enabled": False,
            "imei_privacy_mode": False,
            "apn_uses_tls": False,
            "firewall_enabled": False,
        }
        report = _evaluate(worst)
        assert report.score >= 0

    def test_summary_contains_score(self):
        report = _evaluate({})
        assert "100/100" in report.summary()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_non_dict_raises_type_error(self):
        with pytest.raises(TypeError):
            CellularSecurityAdvisor("not a dict")
