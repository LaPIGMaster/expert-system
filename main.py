"""
CLI entry-point for the Expert System security advisor.

Usage
-----
python main.py                       # Run assessment (uses config files or defaults)
python main.py --configure           # Launch interactive configuration wizard
python main.py --preset balanced     # Generate config from a preset and run assessment

The script reads optional JSON config files for cellular and Bluetooth profiles
(``cellular_profile.json`` and ``bluetooth_profile.json`` in the current
directory).  If they are absent it uses safe example defaults so the advisor
can always demonstrate findings.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from src.expert_system.configure import PRESETS, generate_from_preset, run_wizard
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expert System – Cellular/IP & Bluetooth Security Advisor",
    )
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Launch the interactive configuration wizard.",
    )
    parser.add_argument(
        "--preset",
        choices=list(PRESETS),
        default=None,
        help=(
            "Generate configuration from a built-in preset "
            "(max-security / balanced / minimal) and run the assessment."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --configure: interactive wizard
    if args.configure:
        run_wizard()
        return 0

    # --preset: generate from preset, then assess
    if args.preset:
        generate_from_preset(args.preset)
        print(f"✓ Preset '{args.preset}' written to cellular_profile.json + bluetooth_profile.json\n")

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
