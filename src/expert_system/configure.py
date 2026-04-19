"""
Interactive Configuration Wizard
=================================
Walks the user through a series of plain-English yes/no (and simple-choice)
questions, then writes ``cellular_profile.json`` and
``bluetooth_profile.json`` into the specified output directory.

Can also generate profiles non-interactively from one of three built-in
presets: ``max-security``, ``balanced``, or ``minimal``.
"""

from __future__ import annotations

import json
import os
from typing import Any


# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------

PRESET_MAX_SECURITY: dict[str, dict[str, Any]] = {
    "cellular": {
        "vpn_active": True,
        "vpn_protocol": "wireguard",
        "network_generation": "5G",
        "data_roaming_enabled": False,
        "dns_over_https_enabled": True,
        "imei_privacy_mode": True,
        "apn_uses_tls": True,
        "firewall_enabled": True,
    },
    "bluetooth": {
        "always_discoverable": False,
        "secure_simple_pairing": True,
        "link_encryption_enabled": True,
        "bluetooth_version": 5.3,
        "paired_devices": [],
        "bluetooth_enabled": False,
        "active_connection": False,
        "expected_active": False,
        "ble_address_type": "random",
        "enabled_profiles": [],
    },
}

PRESET_BALANCED: dict[str, dict[str, Any]] = {
    "cellular": {
        "vpn_active": True,
        "vpn_protocol": "wireguard",
        "network_generation": "4G",
        "data_roaming_enabled": False,
        "dns_over_https_enabled": True,
        "imei_privacy_mode": False,
        "apn_uses_tls": True,
        "firewall_enabled": True,
    },
    "bluetooth": {
        "always_discoverable": False,
        "secure_simple_pairing": True,
        "link_encryption_enabled": True,
        "bluetooth_version": 5.0,
        "paired_devices": [],
        "bluetooth_enabled": True,
        "active_connection": True,
        "expected_active": True,
        "ble_address_type": "random",
        "enabled_profiles": ["A2DP", "HFP"],
    },
}

PRESET_MINIMAL: dict[str, dict[str, Any]] = {
    "cellular": {
        "vpn_active": False,
        "vpn_protocol": "",
        "network_generation": "4G",
        "data_roaming_enabled": False,
        "dns_over_https_enabled": False,
        "imei_privacy_mode": False,
        "apn_uses_tls": True,
        "firewall_enabled": False,
    },
    "bluetooth": {
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
    },
}

PRESETS: dict[str, dict[str, dict[str, Any]]] = {
    "max-security": PRESET_MAX_SECURITY,
    "balanced": PRESET_BALANCED,
    "minimal": PRESET_MINIMAL,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ask_yes_no(prompt: str, default: bool = True, *, input_fn=input) -> bool:  # noqa: A002
    """Ask a yes/no question and return a bool."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input_fn(f"{prompt} {hint}: ").strip().lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  → Please answer 'y' or 'n'.")


def _ask_choice(prompt: str, choices: list[str], default: str, *, input_fn=input) -> str:  # noqa: A002
    """Ask the user to pick from a list of options."""
    choices_lower = [c.lower() for c in choices]
    while True:
        answer = input_fn(f"{prompt} ({'/'.join(choices)}) [{default}]: ").strip()
        if answer == "":
            return default
        if answer.lower() in choices_lower:
            return answer
        print(f"  → Please choose one of: {', '.join(choices)}")


def _ask_float(prompt: str, default: float, *, input_fn=input) -> float:  # noqa: A002
    """Ask the user for a decimal number."""
    while True:
        answer = input_fn(f"{prompt} [{default}]: ").strip()
        if answer == "":
            return default
        try:
            return float(answer)
        except ValueError:
            print("  → Please enter a valid number (e.g. 5.3).")


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def configure_cellular_interactive(*, input_fn=input) -> dict[str, Any]:
    """Walk the user through cellular/IP configuration."""
    print("\n── Cellular / IP Security Configuration ──\n")

    vpn_active = _ask_yes_no(
        "Do you have a VPN active on your cellular connection?",
        default=False,
        input_fn=input_fn,
    )
    vpn_protocol = ""
    if vpn_active:
        vpn_protocol = _ask_choice(
            "Which VPN protocol do you use?",
            ["wireguard", "openvpn", "ikev2", "pptp", "l2tp"],
            "wireguard",
            input_fn=input_fn,
        )

    network_generation = _ask_choice(
        "What cellular generation is your device using?",
        ["2G", "3G", "4G", "5G"],
        "4G",
        input_fn=input_fn,
    )

    data_roaming = _ask_yes_no(
        "Is data roaming enabled?",
        default=False,
        input_fn=input_fn,
    )

    dns_over_https = _ask_yes_no(
        "Have you enabled DNS-over-HTTPS (Private DNS)?",
        default=False,
        input_fn=input_fn,
    )

    imei_privacy = _ask_yes_no(
        "Is IMEI/IMSI privacy mode enabled (e.g. GrapheneOS randomisation)?",
        default=False,
        input_fn=input_fn,
    )

    apn_tls = _ask_yes_no(
        "Does your carrier's APN use TLS? (if unsure, answer yes)",
        default=True,
        input_fn=input_fn,
    )

    firewall = _ask_yes_no(
        "Do you have a host-based firewall enabled (e.g. AFWall+, NetGuard)?",
        default=False,
        input_fn=input_fn,
    )

    return {
        "vpn_active": vpn_active,
        "vpn_protocol": vpn_protocol,
        "network_generation": network_generation,
        "data_roaming_enabled": data_roaming,
        "dns_over_https_enabled": dns_over_https,
        "imei_privacy_mode": imei_privacy,
        "apn_uses_tls": apn_tls,
        "firewall_enabled": firewall,
    }


def configure_bluetooth_interactive(*, input_fn=input) -> dict[str, Any]:
    """Walk the user through Bluetooth configuration."""
    print("\n── Bluetooth Security Configuration ──\n")

    bt_enabled = _ask_yes_no(
        "Is Bluetooth currently enabled on your device?",
        default=True,
        input_fn=input_fn,
    )

    always_discoverable = False
    active_connection = False
    expected_active = False
    if bt_enabled:
        always_discoverable = _ask_yes_no(
            "Is your device set to 'always discoverable'?",
            default=False,
            input_fn=input_fn,
        )
        active_connection = _ask_yes_no(
            "Do you have an active Bluetooth connection right now?",
            default=False,
            input_fn=input_fn,
        )
        expected_active = _ask_yes_no(
            "Are you expecting to use Bluetooth soon?",
            default=True,
            input_fn=input_fn,
        )

    ssp = _ask_yes_no(
        "Is Secure Simple Pairing (SSP) enabled? (if unsure, answer yes)",
        default=True,
        input_fn=input_fn,
    )

    encryption = _ask_yes_no(
        "Is link-layer encryption enabled? (if unsure, answer yes)",
        default=True,
        input_fn=input_fn,
    )

    bt_version = _ask_float(
        "What Bluetooth version does your device support?",
        5.0,
        input_fn=input_fn,
    )

    ble_address = _ask_choice(
        "BLE address type (random = private, public = trackable)",
        ["random", "public"],
        "random",
        input_fn=input_fn,
    )

    # Profiles — ask about known risky ones
    enabled_profiles = ["A2DP", "HFP"]
    print("\n  The following Bluetooth profiles are enabled by default: A2DP, HFP")
    for risky in ["OPP", "OBEX", "PAN", "BNEP"]:
        if _ask_yes_no(
            f"  Do you need the {risky} profile?",
            default=False,
            input_fn=input_fn,
        ):
            enabled_profiles.append(risky)

    return {
        "always_discoverable": always_discoverable,
        "secure_simple_pairing": ssp,
        "link_encryption_enabled": encryption,
        "bluetooth_version": bt_version,
        "paired_devices": [],
        "bluetooth_enabled": bt_enabled,
        "active_connection": active_connection,
        "expected_active": expected_active,
        "ble_address_type": ble_address,
        "enabled_profiles": enabled_profiles,
    }


# ---------------------------------------------------------------------------
# Write profiles
# ---------------------------------------------------------------------------


def write_profiles(
    cellular: dict[str, Any],
    bluetooth: dict[str, Any],
    output_dir: str = ".",
) -> tuple[str, str]:
    """
    Persist the two profile dicts to JSON files in *output_dir*.

    Returns the absolute paths of the two files written.
    """
    os.makedirs(output_dir, exist_ok=True)
    cell_path = os.path.join(output_dir, "cellular_profile.json")
    bt_path = os.path.join(output_dir, "bluetooth_profile.json")

    with open(cell_path, "w", encoding="utf-8") as fh:
        json.dump(cellular, fh, indent=2)
        fh.write("\n")

    with open(bt_path, "w", encoding="utf-8") as fh:
        json.dump(bluetooth, fh, indent=2)
        fh.write("\n")

    return os.path.abspath(cell_path), os.path.abspath(bt_path)


# ---------------------------------------------------------------------------
# Preset helper
# ---------------------------------------------------------------------------


def generate_from_preset(name: str, output_dir: str = ".") -> tuple[str, str]:
    """
    Write profiles from a built-in preset.

    Parameters
    ----------
    name : str
        One of ``"max-security"``, ``"balanced"``, ``"minimal"``.
    output_dir : str
        Directory where the JSON files are written.

    Returns
    -------
    tuple[str, str]
        Absolute paths to the cellular and Bluetooth profile files.
    """
    if name not in PRESETS:
        raise ValueError(f"Unknown preset '{name}'. Choose from: {', '.join(PRESETS)}")
    preset = PRESETS[name]
    return write_profiles(preset["cellular"], preset["bluetooth"], output_dir)


# ---------------------------------------------------------------------------
# Full wizard entry-point
# ---------------------------------------------------------------------------


def run_wizard(*, input_fn=input, output_dir: str = ".") -> tuple[str, str]:
    """
    Interactive wizard that asks the user questions and writes config files.

    Returns
    -------
    tuple[str, str]
        Absolute paths to the cellular and Bluetooth profile files.
    """
    print("=" * 50)
    print("  EXPERT SYSTEM – CONFIGURATION WIZARD")
    print("=" * 50)
    print()
    print("Choose a configuration method:")
    print("  1) Answer questions interactively")
    print("  2) Use a preset (max-security / balanced / minimal)")
    print()

    method = _ask_choice("Method", ["1", "2"], "1", input_fn=input_fn)

    if method == "2":
        preset_name = _ask_choice(
            "Which preset?",
            ["max-security", "balanced", "minimal"],
            "balanced",
            input_fn=input_fn,
        )
        cell_path, bt_path = generate_from_preset(preset_name, output_dir)
    else:
        cellular = configure_cellular_interactive(input_fn=input_fn)
        bluetooth = configure_bluetooth_interactive(input_fn=input_fn)
        cell_path, bt_path = write_profiles(cellular, bluetooth, output_dir)

    print()
    print("✓ Configuration saved!")
    print(f"  Cellular profile : {cell_path}")
    print(f"  Bluetooth profile: {bt_path}")
    print()
    print("Run 'python main.py' to see your security assessment.")
    return cell_path, bt_path
