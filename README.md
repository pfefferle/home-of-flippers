# Wall of Flippers for Home Assistant

Passively detect nearby **Flipper Zero** devices and **BLE advertisement spam attacks**
(Sour Apple, Windows Swift Pair, Samsung, Android Fast Pair, LoveSpouse, HID flood)
using Home Assistant's Bluetooth stack — including **ESPHome / Shelly Bluetooth proxies**.

Inspired by [Wall of Flippers](https://github.com/k3yomi/Wall-of-Flippers) by Kiyomi & Jbohack.

## Requirements

- Home Assistant 2024.8.0+
- The `bluetooth` integration active, with at least one local adapter or Bluetooth proxy.

## Installation (HACS)

1. HACS → Integrations → ⋮ → Custom repositories → add this repo as an **Integration**.
2. Install **Wall of Flippers**, restart Home Assistant.
3. Settings → Devices & Services → Add Integration → **Wall of Flippers**.

## Entities

- `binary_sensor` Flipper Zero Detected / BLE Attack Detected
- `sensor` Flippers Nearby / BLE Attacks per Minute / Last Attack Type
- `device_tracker` one per detected Flipper (variant, RSSI, detection type, first/last seen)
- `event` BLE Attack (event type = attack kind)

## Events (for automations)

- `wall_of_flippers_flipper_detected` — `{address, name, variant, detection_type, rssi, source}`
- `wall_of_flippers_attack_detected` — `{attack_type, matched_signature, address, rssi, source}`

## Options

RSSI floor, stale timeout, attack-active window, attack-detection toggle, and
anti-spoof rate-limit count/window are configurable via the integration's
**Configure** dialog.

## How detection works

Flipper Zero devices are identified from their advertised 128-bit service UUID
(`00003081/82/83-…` → Black / White / Transparent; other `0000308x-…` →
Spoofed/Unknown), refined by name (`flipper…`) or the Flipper Devices Inc MAC
OUIs (`80:e1:26`, `80:e1:27`, `0c:fa:22`). BLE attacks are matched by
wildcard-comparing reconstructed advertisement hex (manufacturer data, service
data, service UUIDs) against known spam signatures.

## Disclaimer

Detection is heuristic and signature-based; false positives/negatives are possible.
This tool is passive and detection-only.
