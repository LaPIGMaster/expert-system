"""
Unit tests for the configuration wizard and presets.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from src.expert_system.configure import (
    PRESETS,
    configure_bluetooth_interactive,
    configure_cellular_interactive,
    generate_from_preset,
    run_wizard,
    write_profiles,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_input_fn(answers: list[str]):
    """Return a callable that feeds pre-canned answers one at a time."""
    it = iter(answers)
    return lambda _prompt: next(it)


# ---------------------------------------------------------------------------
# write_profiles
# ---------------------------------------------------------------------------


class TestWriteProfiles:
    def test_creates_both_json_files(self, tmp_path):
        cell = {"vpn_active": True}
        bt = {"bluetooth_enabled": False}
        cell_path, bt_path = write_profiles(cell, bt, str(tmp_path))

        assert os.path.isfile(cell_path)
        assert os.path.isfile(bt_path)

    def test_files_are_valid_json(self, tmp_path):
        cell = {"vpn_active": True, "vpn_protocol": "wireguard"}
        bt = {"bluetooth_enabled": False}
        cell_path, bt_path = write_profiles(cell, bt, str(tmp_path))

        with open(cell_path) as fh:
            loaded_cell = json.load(fh)
        with open(bt_path) as fh:
            loaded_bt = json.load(fh)

        assert loaded_cell == cell
        assert loaded_bt == bt

    def test_creates_output_directory(self, tmp_path):
        out = str(tmp_path / "nested" / "dir")
        write_profiles({"a": 1}, {"b": 2}, out)
        assert os.path.isdir(out)


# ---------------------------------------------------------------------------
# generate_from_preset
# ---------------------------------------------------------------------------


class TestGenerateFromPreset:
    @pytest.mark.parametrize("preset_name", list(PRESETS))
    def test_generates_valid_files(self, tmp_path, preset_name):
        cell_path, bt_path = generate_from_preset(preset_name, str(tmp_path))
        with open(cell_path) as fh:
            cell = json.load(fh)
        with open(bt_path) as fh:
            bt = json.load(fh)

        assert "vpn_active" in cell
        assert "bluetooth_enabled" in bt

    def test_unknown_preset_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown preset"):
            generate_from_preset("nonexistent", str(tmp_path))

    def test_max_security_vpn_is_active(self, tmp_path):
        cell_path, _ = generate_from_preset("max-security", str(tmp_path))
        with open(cell_path) as fh:
            cell = json.load(fh)
        assert cell["vpn_active"] is True
        assert cell["vpn_protocol"] == "wireguard"

    def test_minimal_vpn_is_inactive(self, tmp_path):
        cell_path, _ = generate_from_preset("minimal", str(tmp_path))
        with open(cell_path) as fh:
            cell = json.load(fh)
        assert cell["vpn_active"] is False


# ---------------------------------------------------------------------------
# Interactive cellular configuration
# ---------------------------------------------------------------------------


class TestCellularInteractive:
    def test_all_yes_answers(self):
        # yes VPN → wireguard → 5G → no roaming → yes DoH → yes IMEI → yes TLS → yes firewall
        answers = ["y", "wireguard", "5G", "n", "y", "y", "y", "y"]
        profile = configure_cellular_interactive(input_fn=_make_input_fn(answers))
        assert profile["vpn_active"] is True
        assert profile["vpn_protocol"] == "wireguard"
        assert profile["network_generation"] == "5G"
        assert profile["data_roaming_enabled"] is False
        assert profile["dns_over_https_enabled"] is True
        assert profile["imei_privacy_mode"] is True
        assert profile["apn_uses_tls"] is True
        assert profile["firewall_enabled"] is True

    def test_no_vpn_skips_protocol(self):
        # no VPN → 4G → no roaming → no DoH → no IMEI → yes TLS → no firewall
        answers = ["n", "4G", "n", "n", "n", "y", "n"]
        profile = configure_cellular_interactive(input_fn=_make_input_fn(answers))
        assert profile["vpn_active"] is False
        assert profile["vpn_protocol"] == ""

    def test_defaults_accepted(self):
        # All blank (accept defaults)
        answers = ["", "", "", "", "", "", ""]
        profile = configure_cellular_interactive(input_fn=_make_input_fn(answers))
        # defaults: vpn_active=False (default for yes_no with default=False)
        assert profile["vpn_active"] is False


# ---------------------------------------------------------------------------
# Interactive Bluetooth configuration
# ---------------------------------------------------------------------------


class TestBluetoothInteractive:
    def test_bt_enabled_full_answers(self):
        # BT on → not discoverable → active conn → expecting use → SSP yes → encryption yes
        # → version 5.3 → random → no OPP → no OBEX → no PAN → no BNEP
        answers = ["y", "n", "y", "y", "y", "y", "5.3", "random", "n", "n", "n", "n"]
        profile = configure_bluetooth_interactive(input_fn=_make_input_fn(answers))
        assert profile["bluetooth_enabled"] is True
        assert profile["always_discoverable"] is False
        assert profile["bluetooth_version"] == 5.3
        assert "OPP" not in profile["enabled_profiles"]

    def test_bt_disabled_skips_sub_questions(self):
        # BT off → SSP yes → encryption yes → version 5.0 → random → no risky profiles × 4
        answers = ["n", "y", "y", "5.0", "random", "n", "n", "n", "n"]
        profile = configure_bluetooth_interactive(input_fn=_make_input_fn(answers))
        assert profile["bluetooth_enabled"] is False
        assert profile["always_discoverable"] is False
        assert profile["active_connection"] is False

    def test_risky_profiles_added(self):
        # BT on → not discoverable → no conn → not expecting → SSP yes → enc yes
        # → version 5.0 → random → yes OPP → no OBEX → yes PAN → no BNEP
        answers = ["y", "n", "n", "n", "y", "y", "5.0", "random", "y", "n", "y", "n"]
        profile = configure_bluetooth_interactive(input_fn=_make_input_fn(answers))
        assert "OPP" in profile["enabled_profiles"]
        assert "PAN" in profile["enabled_profiles"]
        assert "OBEX" not in profile["enabled_profiles"]


# ---------------------------------------------------------------------------
# Full wizard (preset path)
# ---------------------------------------------------------------------------


class TestRunWizard:
    def test_preset_path(self, tmp_path):
        # Choose method 2 → preset balanced
        answers = ["2", "balanced"]
        cell_path, bt_path = run_wizard(
            input_fn=_make_input_fn(answers),
            output_dir=str(tmp_path),
        )
        assert os.path.isfile(cell_path)
        assert os.path.isfile(bt_path)

    def test_interactive_path(self, tmp_path):
        # method 1 → full cellular answers → full bluetooth answers
        answers = [
            "1",
            # Cellular: no VPN, 4G, no roaming, no DoH, no IMEI, yes TLS, no firewall
            "n", "4G", "n", "n", "n", "y", "n",
            # Bluetooth: BT on, not discoverable, no conn, not expecting, SSP yes,
            # enc yes, 5.0, random, no×4 risky profiles
            "y", "n", "n", "n", "y", "y", "5.0", "random", "n", "n", "n", "n",
        ]
        cell_path, bt_path = run_wizard(
            input_fn=_make_input_fn(answers),
            output_dir=str(tmp_path),
        )
        with open(cell_path) as fh:
            cell = json.load(fh)
        assert cell["vpn_active"] is False
        assert cell["network_generation"] == "4G"


# ---------------------------------------------------------------------------
# main.py CLI flags
# ---------------------------------------------------------------------------


class TestMainCLI:
    def test_preset_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from main import main

        exit_code = main(["--preset", "max-security"])
        assert exit_code == 0  # max-security should be fully secure
        assert os.path.isfile(tmp_path / "cellular_profile.json")
        assert os.path.isfile(tmp_path / "bluetooth_profile.json")

    def test_no_args_runs_assessment(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from main import main

        exit_code = main([])
        # With defaults (insecure) → exit 1
        assert exit_code == 1

    def test_preset_balanced(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from main import main

        exit_code = main(["--preset", "balanced"])
        # balanced has no CRITICAL/HIGH so should be secure
        assert exit_code == 0
