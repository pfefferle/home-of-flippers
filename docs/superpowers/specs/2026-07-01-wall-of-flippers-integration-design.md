# Wall of Flippers — Home Assistant Integration Design

**Date:** 2026-07-01
**Status:** Approved
**Target:** HACS custom integration (`custom_components/wall_of_flippers`)

## 1. Purpose

Port [Wall of Flippers](https://github.com/k3yomi/Wall-of-Flippers) detection to Home
Assistant. Passively detect nearby **Flipper Zero** devices and **BLE
advertisement spam/DoS attacks** using advertisements received through Home
Assistant's Bluetooth stack — including advertisements relayed by **ESPHome /
Shelly Bluetooth proxies**. No pairing, no polling, no active scanning by us.

Scope (confirmed): detect **both** Flipper devices and BLE attacks. Surface them
as **dynamic per-device entities + aggregate entities + bus events**.

## 2. How advertisements reach us

Home Assistant's `bluetooth` integration aggregates advertisements from local
adapters and from Bluetooth proxies. Integrations subscribe with:

```python
bluetooth.async_register_callback(
    hass, _on_advertisement, BluetoothCallbackMatcher(connectable=False),
    bluetooth.BluetoothScanningMode.PASSIVE,
)
```

Each callback delivers a `BluetoothServiceInfoBleak` exposing: `name`,
`address`, `rssi`, `service_uuids`, `service_data` (`{uuid: bytes}`),
`manufacturer_data` (`{company_id: bytes}`), and `source` (the adapter/proxy
that heard it). We use a broad matcher and do our own filtering in
`detection.py`, because a Flipper or an attack has no single stable matcher.

## 3. Detection engine — `detection.py` (framework-free, pure functions)

Ported 1:1 from upstream `utils/wof_library.py` and `utils/wof_cache.py`.

### 3.1 Flipper Zero identification

`identify_flipper(info) -> FlipperInfo | None`

- **Variant** from a matched 128-bit service UUID:
  - `00003081-0000-1000-8000-00805f9b34fb` → `Black`
  - `00003082-0000-1000-8000-00805f9b34fb` → `White`
  - `00003083-0000-1000-8000-00805f9b34fb` → `Transparent`
  - other `0000308x-0000-1000-8000-00805f9b34fb` → `Spoofed/Unknown`
- **Detection type** (priority order matching upstream):
  - name lowercased starts with `flipper` → `Name`
  - address OUI in {`80:e1:26`, `80:e1:27`, `0c:fa:22`} (Flipper Devices Inc) → `Address`
  - else a matched service UUID → `Identifier`
- Returns `FlipperInfo(address, name, variant, detection_type, uid, rssi)` or
  `None` if nothing matches.

### 3.2 BLE attack matching

`match_attacks(info) -> list[AttackHit]`

Reconstruct candidate hex strings from the advertisement and wildcard-match them
against the signature table. Candidate strings:

- **manufacturer_data**: for each `(company_id, data)`, build
  `company_id` as little-endian 2-byte hex + `data.hex()`
  (e.g. Apple `0x004c` → `4c00` + payload; Microsoft `0x0006` → `0600`;
  Samsung `0x0075` → `7500`).
- **service_data**: `uuid` (16-bit short form when applicable) + `data.hex()`
  (e.g. Google/Android Fast Pair `fe2c`).
- **service_uuids**: the UUID string itself (e.g. HID `00001812-…`).

Wildcard rule (upstream): `_` matches any single hex nibble; a signature matches
when every non-`_` nibble equals the candidate and the candidate is at least as
long as the signature's non-wildcard portion.

Signature table (ported; extensible in `const.py`):

| Signature (prefix, `_`=wildcard nibble) | Type |
|---|---|
| `00001812-0000-1000-8000-00805f9b34fb` | `BLE_HUMAN_INTERFACE_DEVICE` |
| `4c000719010_2055_______________` | `BLE_APPLE_DEVICE_POPUP_CLOSE` |
| `4c000f05c00____________________` | `BLE_APPLE_ACTION_MODAL_LONG` |
| `4c00071907_____________________` | `BLE_APPLE_DEVICE_CONNECT` |
| `4c0004042a0000000f05c1__604c950` | `BLE_APPLE_DEVICE_SETUP` |
| `2cfe___________________________` | `BLE_ANDROID_DEVICE_CONNECT` |
| `750042098102141503210109____01_` | `BLE_SAMSUNG_BUDS_POPUP_LONG` |
| `7500010002000101ff000043_______` | `BLE_SAMSUNG_WATCH_PAIR_LONG` |
| `0600030080_____________________` | `BLE_WINDOWS_SWIFT_PAIR_SHORT` |
| `ff006db643ce97fe427c___________` | `BLE_LOVE_TOYS_SHORT_DISTANCE` |

`AttackHit(attack_type, matched_signature, address, rssi)`.

## 4. Runtime state — `detector.py`

A single object owned by the config entry, stored in `entry.runtime_data`.

- `live_flippers: dict[str, FlipperState]` keyed by MAC — first_seen, last_seen,
  rssi, variant, detection_type, name, uid.
- `attacks: deque[AttackHit + timestamp]` — recent attacks within the auto-off
  window.
- **RSSI floor**: ignore advertisements below the configured floor.
- **Rate-limit / anti-spoof** (ported): if ≥ `rate_limit_count` (default 3) *new*
  Flipper MACs appear within `rate_limit_window` (default 5 s), enter a
  rate-limited state; Flippers appearing during that burst are flagged as
  suspected spoof-flood rather than trusted as distinct devices.

On each advertisement the detector: applies RSSI floor → runs `identify_flipper`
and `match_attacks` → updates state → notifies entities (via dispatcher) → fires
bus events. A periodic tick expires stale flippers (last_seen older than the
stale timeout) and clears the attack window.

## 5. Entities & events

### Aggregate (created at setup)
- `binary_sensor` **Flipper Zero Detected** — on while any live (non-stale) Flipper exists.
- `binary_sensor` **BLE Attack Detected** — on for `attack_window` seconds after the last attack.
- `sensor` **Flippers Nearby** — count of live flippers.
- `sensor` **BLE Attacks per Minute** — rolling count.
- `sensor` **Last Attack Type** — most recent `attack_type` (or `none`).

### Dynamic (`device_tracker`, one per Flipper)
- Created the first time a new MAC is seen; registered under an HA *device*.
- State `home` when last_seen within stale timeout, else `not_home`.
- Attributes: variant, rssi, detection_type, name, uid, first_seen, last_seen, source.
- Uses `RestoreEntity` so known Flippers survive restarts.

### `event` entity
- **BLE Attack** with `event_types` = the attack-type list; each match triggers
  the event with `attack_type`, `matched_signature`, `address`, `rssi`.

### Bus events (for automations)
- `wall_of_flippers_flipper_detected` — `{address, name, variant, detection_type, rssi, source}`
- `wall_of_flippers_attack_detected` — `{attack_type, matched_signature, address, rssi, source}`

## 6. Config flow & options

- **Setup**: single instance (`single_config_entry`). No user input required;
  aborts with a helpful message if the `bluetooth` integration is unavailable.
- **Options flow**:
  - `rssi_floor` (default `-90`)
  - `stale_timeout` seconds (default `300`)
  - `attack_window` seconds (default `60`)
  - `enable_attack_detection` (default `true`)
  - `rate_limit_count` (default `3`), `rate_limit_window` seconds (default `5`)

## 7. `manifest.json`

```json
{
  "domain": "wall_of_flippers",
  "name": "Wall of Flippers",
  "codeowners": [],
  "config_flow": true,
  "dependencies": ["bluetooth"],
  "documentation": "https://github.com/.../hassio-wall-of-flippers",
  "iot_class": "local_push",
  "issue_tracker": "https://github.com/.../hassio-wall-of-flippers/issues",
  "requirements": [],
  "version": "0.1.0"
}
```

## 8. Repository layout

```
custom_components/wall_of_flippers/
  __init__.py  manifest.json  const.py  detection.py  detector.py
  config_flow.py  binary_sensor.py  sensor.py  device_tracker.py  event.py
  strings.json  translations/en.json
hacs.json
README.md
LICENSE
.github/workflows/validate.yml   # hacs/action + hassfest
tests/                            # pytest + pytest-homeassistant-custom-component
```

## 9. Testing strategy

- **Unit** (`detection.py`): construct `BluetoothServiceInfoBleak` fixtures for a
  real Flipper (each variant, plus name-only and OUI-only), a spoofed UUID, and
  one advertisement per attack signature; assert correct classification and no
  false positives on benign advertisements.
- **Detector**: rate-limit burst behavior, stale expiry, attack-window expiry.
- **Integration**: config-flow (single instance, options) and entity creation
  via `pytest-homeassistant-custom-component`, injecting advertisements through
  the bluetooth callback.
- **CI**: GitHub Action running `hacs/action` (validity) and `hassfest`.

## 10. Non-goals (YAGNI)

- No advertisement *sending* / attacking / BLE-chat (upstream has these; we are
  detection-only).
- No adopting/controlling a specific Flipper as a normal BLE device.
- No historical database beyond HA's own recorder/logbook.
