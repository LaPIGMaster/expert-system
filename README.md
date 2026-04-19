# expert-system

A rule-based security expert system that audits your phone's **cellular/IP** and **Bluetooth** configuration and tells you exactly what to fix to stay ahead of hackers.

## Features

| Domain | Rules | What it checks |
|--------|-------|----------------|
| Cellular / IP | 8 rules | VPN (active + protocol strength), network generation (2G/3G/4G/5G), data roaming, DNS-over-HTTPS, IMEI privacy, APN TLS, host firewall |
| Bluetooth | 8 rules | Discoverability, Secure Simple Pairing, link-layer encryption, BT version (KNOB/BIAS mitigations), paired-device allowlist, BLE MAC privacy, risky profiles |

Each finding comes with a **severity** (CRITICAL / HIGH / MEDIUM / LOW), a plain-English description, and a concrete **recommendation**.

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the advisor (uses safe example defaults)
python main.py
```

## Configuration

There are **three ways** to configure the expert system:

### 1. Interactive wizard (recommended)

```bash
python main.py --configure
```

The wizard asks you plain-English yes/no questions about your setup and writes
`cellular_profile.json` + `bluetooth_profile.json` for you.  You can also
choose a built-in preset from the wizard menu.

### 2. Quick preset

```bash
# Maximum security — VPN on, 5G, DoH, IMEI privacy, BT off
python main.py --preset max-security

# Balanced — VPN on, 4G, DoH, BT on with safe defaults
python main.py --preset balanced

# Minimal — no VPN, standard 4G, BT on (shows what you should fix)
python main.py --preset minimal
```

### 3. Manual JSON files

Create `cellular_profile.json` and/or `bluetooth_profile.json` in the working
directory.  The advisor picks them up automatically.  See the `examples/`
folder for ready-to-use templates.

**cellular_profile.json example**
```json
{
  "vpn_active": true,
  "vpn_protocol": "wireguard",
  "network_generation": "5G",
  "data_roaming_enabled": false,
  "dns_over_https_enabled": true,
  "imei_privacy_mode": true,
  "apn_uses_tls": true,
  "firewall_enabled": true
}
```

**bluetooth_profile.json example**
```json
{
  "always_discoverable": false,
  "secure_simple_pairing": true,
  "link_encryption_enabled": true,
  "bluetooth_version": 5.3,
  "paired_devices": [{"name": "My Headphones", "trusted": true}],
  "bluetooth_enabled": true,
  "active_connection": true,
  "expected_active": true,
  "ble_address_type": "random",
  "enabled_profiles": ["A2DP", "HFP"]
}
```

## Running the tests

```bash
python -m pytest tests/ -v
```

All 104 tests should pass.

## Project layout

```
src/
  expert_system/
    advisors/
      cellular.py    – Cellular/IP security rules & advisor
      bluetooth.py   – Bluetooth security rules & advisor
    configure.py     – Interactive wizard & presets
    expert_system.py – Orchestrator (runs both advisors)
examples/            – Ready-to-use JSON profile templates
tests/
  test_cellular.py
  test_bluetooth.py
  test_configure.py
  test_expert_system.py
main.py              – CLI entry-point
requirements.txt
```

