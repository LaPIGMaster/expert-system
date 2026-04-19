"""
Integration tests for the ExpertSystem orchestrator.
"""

import pytest

from src.expert_system.expert_system import ExpertSystem, ConsolidatedReport


SECURE_CELLULAR = {
    "vpn_active": True,
    "vpn_protocol": "wireguard",
    "network_generation": "5G",
    "data_roaming_enabled": False,
    "dns_over_https_enabled": True,
    "imei_privacy_mode": True,
    "apn_uses_tls": True,
    "firewall_enabled": True,
}

SECURE_BLUETOOTH = {
    "always_discoverable": False,
    "secure_simple_pairing": True,
    "link_encryption_enabled": True,
    "bluetooth_version": 5.3,
    "paired_devices": [{"name": "Headphones", "trusted": True}],
    "bluetooth_enabled": True,
    "active_connection": True,
    "expected_active": True,
    "ble_address_type": "random",
    "enabled_profiles": ["A2DP", "HFP"],
}


class TestExpertSystemIntegration:
    def test_fully_secure_config(self):
        system = ExpertSystem(SECURE_CELLULAR, SECURE_BLUETOOTH)
        report = system.run()
        assert report.is_secure() is True
        assert report.overall_score == 100

    def test_insecure_cellular_affects_overall(self):
        cellular = {**SECURE_CELLULAR, "vpn_active": False, "vpn_protocol": ""}
        system = ExpertSystem(cellular, SECURE_BLUETOOTH)
        report = system.run()
        assert report.is_secure() is False
        assert report.overall_score < 100

    def test_insecure_bluetooth_affects_overall(self):
        bluetooth = {**SECURE_BLUETOOTH, "secure_simple_pairing": False}
        system = ExpertSystem(SECURE_CELLULAR, bluetooth)
        report = system.run()
        assert report.is_secure() is False

    def test_summary_includes_both_sections(self):
        system = ExpertSystem(SECURE_CELLULAR, SECURE_BLUETOOTH)
        report = system.run()
        summary = report.summary()
        assert "Cellular" in summary
        assert "Bluetooth" in summary
        assert "OVERALL" in summary

    def test_overall_score_is_average(self):
        # Force cellular to lose 25 points (one CRITICAL) and bluetooth to be perfect
        cellular = {**SECURE_CELLULAR, "vpn_active": False, "vpn_protocol": ""}
        system = ExpertSystem(cellular, SECURE_BLUETOOTH)
        report = system.run()
        expected = (report.cellular.score + report.bluetooth.score) // 2
        assert report.overall_score == expected
