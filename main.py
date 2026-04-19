"""
CLI entry-point for the Expert System security advisor.

Usage
-----
python main.py

The script reads optional JSON config files for cellular and Bluetooth profiles
(``cellular_profile.json`` and ``bluetooth_profile.json`` in the current
directory).  If they are absent it uses safe example defaults so the advisor
can always demonstrate findings.
"""

from __future__ import annotations

import json
import os
import sys

from src.expert_system.expert_system import ExpertSystem

# ---------------------------------------------------------------------------
# Example profiles used when no config files are present.
# These represent a *typical insecure* phone setup so the advisor has
# something meaningful to report out-of-the-box.
# ---------------------------------------------------------------------------

DEFAULT_CELLULAR_PROFILE: dict = {
    "vpn_active": False,
    "vpn_protocol": "",
    "network_generation": "4G",
    "data_roaming_enabled": False,
    "dns_over_https_enabled": False,
    "imei_privacy_mode": False,
    "apn_uses_tls": True,
    "firewall_enabled": False,
}

DEFAULT_BLUETOOTH_PROFILE: dict = {
    "always_discoverable": False,
    "secure_simple_pairing": True,
    "link_encryption_enabled": True,
    "bluetooth_version": 5.0,
    "paired_devices": [],
    "bluetooth_enabled": True,
    "active_connection": False,
    "expected_active": False,
    "ble_address_type": "random",
    "enabled_profiles": ["A2DP", "HFP"],
}


def _load_profile(filename: str, default: dict) -> dict:
    if os.path.exists(filename):
        with open(filename, encoding="utf-8") as fh:
            return json.load(fh)
    return default


def main() -> int:
    cellular_profile = _load_profile("cellular_profile.json", DEFAULT_CELLULAR_PROFILE)
    bluetooth_profile = _load_profile("bluetooth_profile.json", DEFAULT_BLUETOOTH_PROFILE)

    system = ExpertSystem(
        cellular_profile=cellular_profile,
        bluetooth_profile=bluetooth_profile,
    )
    report = system.run()
    print(report.summary())
    return 0 if report.is_secure() else 1


if __name__ == "__main__":
    sys.exit(main())
