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

### Custom profile

Create `cellular_profile.json` and/or `bluetooth_profile.json` in the working directory.  The advisor picks them up automatically.

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

All 84 tests should pass.

## Project layout

```
src/
  expert_system/
    advisors/
      cellular.py   – Cellular/IP security rules & advisor
      bluetooth.py  – Bluetooth security rules & advisor
    expert_system.py – Orchestrator (runs both advisors)
tests/
  test_cellular.py
  test_bluetooth.py
  test_expert_system.py
main.py             – CLI entry-point
requirements.txt
```

