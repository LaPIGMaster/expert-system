"""
Unit tests for the Bluetooth Security Advisor.
"""

import pytest

from src.expert_system.advisors.bluetooth import (
    BluetoothSecurityAdvisor,
    BluetoothSecurityReport,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECURE_PROFILE = {
    "always_discoverable": False,
    "secure_simple_pairing": True,
    "link_encryption_enabled": True,
    "bluetooth_version": 5.3,
    "paired_devices": [{"name": "My Headphones", "trusted": True}],
    "bluetooth_enabled": True,
    "active_connection": True,
    "expected_active": True,
    "ble_address_type": "random",
    "enabled_profiles": ["A2DP", "HFP"],
}


def _evaluate(overrides: dict) -> BluetoothSecurityReport:
    profile = {**SECURE_PROFILE, **overrides}
    return BluetoothSecurityAdvisor(profile).evaluate()


def _finding_ids(report: BluetoothSecurityReport) -> set[str]:
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
# B-001: Discoverability
# ---------------------------------------------------------------------------


class TestDiscoverability:
    def test_always_discoverable_raises_b001(self):
        report = _evaluate({"always_discoverable": True})
        assert "B-001" in _finding_ids(report)

    def test_b001_is_high_severity(self):
        report = _evaluate({"always_discoverable": True})
        finding = next(f for f in report.findings if f.rule_id == "B-001")
        assert finding.severity == Severity.HIGH

    def test_not_discoverable_clears_b001(self):
        report = _evaluate({"always_discoverable": False})
        assert "B-001" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-002: Secure Simple Pairing
# ---------------------------------------------------------------------------


class TestSecureSimplePairing:
    def test_no_ssp_raises_b002(self):
        report = _evaluate({"secure_simple_pairing": False})
        assert "B-002" in _finding_ids(report)

    def test_b002_is_critical(self):
        report = _evaluate({"secure_simple_pairing": False})
        finding = next(f for f in report.findings if f.rule_id == "B-002")
        assert finding.severity == Severity.CRITICAL

    def test_ssp_enabled_clears_b002(self):
        report = _evaluate({"secure_simple_pairing": True})
        assert "B-002" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-003: Link encryption
# ---------------------------------------------------------------------------


class TestLinkEncryption:
    def test_no_encryption_raises_b003(self):
        report = _evaluate({"link_encryption_enabled": False})
        assert "B-003" in _finding_ids(report)

    def test_b003_is_critical(self):
        report = _evaluate({"link_encryption_enabled": False})
        finding = next(f for f in report.findings if f.rule_id == "B-003")
        assert finding.severity == Severity.CRITICAL

    def test_encryption_enabled_clears_b003(self):
        report = _evaluate({"link_encryption_enabled": True})
        assert "B-003" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-004: Bluetooth version
# ---------------------------------------------------------------------------


class TestBluetoothVersion:
    @pytest.mark.parametrize("version", [2.0, 2.1, 3.0, 4.0, 4.1])
    def test_old_version_raises_b004(self, version):
        report = _evaluate({"bluetooth_version": version})
        assert "B-004" in _finding_ids(report)

    @pytest.mark.parametrize("version", [4.2, 5.0, 5.3])
    def test_modern_version_clears_b004(self, version):
        report = _evaluate({"bluetooth_version": version})
        assert "B-004" not in _finding_ids(report)

    def test_invalid_version_no_crash(self):
        report = _evaluate({"bluetooth_version": "unknown"})
        assert "B-004" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-005: Paired device allowlist
# ---------------------------------------------------------------------------


class TestPairedDeviceAllowlist:
    def test_untrusted_device_raises_b005(self):
        report = _evaluate({
            "paired_devices": [{"name": "Suspicious Speaker", "trusted": False}]
        })
        assert "B-005" in _finding_ids(report)

    def test_trusted_devices_clear_b005(self):
        report = _evaluate({
            "paired_devices": [
                {"name": "My Headphones", "trusted": True},
                {"name": "My Watch", "trusted": True},
            ]
        })
        assert "B-005" not in _finding_ids(report)

    def test_empty_paired_list_clears_b005(self):
        report = _evaluate({"paired_devices": []})
        assert "B-005" not in _finding_ids(report)

    def test_non_list_paired_devices_no_crash(self):
        report = _evaluate({"paired_devices": "not-a-list"})
        assert "B-005" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-006: Bluetooth disabled when unused
# ---------------------------------------------------------------------------


class TestBluetoothUnused:
    def test_bt_on_no_connection_raises_b006(self):
        report = _evaluate({
            "bluetooth_enabled": True,
            "active_connection": False,
            "expected_active": False,
        })
        assert "B-006" in _finding_ids(report)

    def test_bt_on_with_connection_clears_b006(self):
        report = _evaluate({
            "bluetooth_enabled": True,
            "active_connection": True,
            "expected_active": True,
        })
        assert "B-006" not in _finding_ids(report)

    def test_bt_off_no_b006(self):
        report = _evaluate({
            "bluetooth_enabled": False,
            "active_connection": False,
            "expected_active": False,
        })
        assert "B-006" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-007: BLE privacy
# ---------------------------------------------------------------------------


class TestBlePrivacy:
    def test_public_address_raises_b007(self):
        report = _evaluate({"ble_address_type": "public"})
        assert "B-007" in _finding_ids(report)

    def test_random_address_clears_b007(self):
        report = _evaluate({"ble_address_type": "random"})
        assert "B-007" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# B-008: Risky profiles
# ---------------------------------------------------------------------------


class TestRiskyProfiles:
    @pytest.mark.parametrize("profile_name", ["OBEX", "OPP", "PAN", "BNEP", "obex"])
    def test_risky_profile_raises_b008(self, profile_name):
        report = _evaluate({"enabled_profiles": [profile_name]})
        assert "B-008" in _finding_ids(report)

    def test_safe_profiles_clear_b008(self):
        report = _evaluate({"enabled_profiles": ["A2DP", "HFP", "AVRCP"]})
        assert "B-008" not in _finding_ids(report)

    def test_no_profiles_no_b008(self):
        report = _evaluate({"enabled_profiles": []})
        assert "B-008" not in _finding_ids(report)


# ---------------------------------------------------------------------------
# Score / status helpers
# ---------------------------------------------------------------------------


class TestScoring:
    def test_score_decreases_with_findings(self):
        secure = _evaluate({}).score
        insecure = _evaluate({"secure_simple_pairing": False}).score
        assert insecure < secure

    def test_score_never_negative(self):
        worst = {
            "always_discoverable": True,
            "secure_simple_pairing": False,
            "link_encryption_enabled": False,
            "bluetooth_version": 2.0,
            "paired_devices": [{"name": "Rogue", "trusted": False}],
            "bluetooth_enabled": True,
            "active_connection": False,
            "expected_active": False,
            "ble_address_type": "public",
            "enabled_profiles": ["OPP", "PAN", "BNEP", "OBEX"],
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
            BluetoothSecurityAdvisor(42)
