# Wall of Flippers Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a HACS custom integration that passively detects nearby Flipper Zero devices and BLE advertisement spam attacks from advertisements received via Home Assistant's Bluetooth stack (including ESPHome/Shelly Bluetooth proxies).

**Architecture:** A single-instance hub integration registers one broad passive Bluetooth callback. A framework-free `detection.py` classifies each advertisement; a `detector.py` holds runtime state (live flippers, attack window, anti-spoof rate limit) and pushes updates to entities via dispatcher + fires bus events. Entities: aggregate binary_sensors/sensors, dynamic per-Flipper device_trackers, and an event entity.

**Tech Stack:** Python 3.12+, Home Assistant `bluetooth` integration (`habluetooth`/`BluetoothServiceInfoBleak`), pytest, pytest-homeassistant-custom-component.

## Global Constraints

- Integration domain: `wall_of_flippers` (exact, used in all paths/consts).
- `manifest.json`: `"dependencies": ["bluetooth"]`, `"iot_class": "local_push"`, `"config_flow": true`, `"version": "0.1.0"`.
- Detection-only. No advertisement sending, attacking, or BLE-chat.
- `detection.py` MUST NOT import `homeassistant.*` (pure, independently unit-testable).
- All hex comparisons are lowercase; wildcard `_` matches exactly one hex nibble; a signature matches a candidate when `len(candidate) >= len(signature)` and every non-`_` position is equal.
- Flipper classification REQUIRES a `0000308x-…-00805f9b34fb` service UUID present (matches upstream; avoids name-only false positives).
- Repo URLs/codeowners in `manifest.json`/`hacs.json` are placeholders `REPLACE_ME` until the GitHub repo path is known.

---

### Task 1: Scaffold repository, constants, and CI

**Files:**
- Create: `custom_components/wall_of_flippers/__init__.py` (temporary minimal, replaced in Task 4)
- Create: `custom_components/wall_of_flippers/manifest.json`
- Create: `custom_components/wall_of_flippers/const.py`
- Create: `hacs.json`
- Create: `.github/workflows/validate.yml`
- Create: `requirements-test.txt`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Test: `tests/test_const.py`

**Interfaces:**
- Produces: all constants in `const.py` (`DOMAIN`, `PLATFORMS`, `FLIPPER_VARIANTS`, `BASE_UUID_SUFFIX`, `FLIPPER_UUID_PREFIX`, `FLIPPER_OUIS`, `ATTACK_SIGNATURES`, `ATTACK_TYPES`, event names, signal names, `CONF_*`/`DEFAULT_*`).

- [ ] **Step 1: Write `const.py`**

```python
"""Constants for the Wall of Flippers integration."""

DOMAIN = "wall_of_flippers"

PLATFORMS = ["binary_sensor", "sensor", "device_tracker", "event"]

# --- Flipper Zero identification ---------------------------------------------
BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"
FLIPPER_UUID_PREFIX = "0000308"
FLIPPER_VARIANTS = {
    "00003081" + BASE_UUID_SUFFIX: "Black",
    "00003082" + BASE_UUID_SUFFIX: "White",
    "00003083" + BASE_UUID_SUFFIX: "Transparent",
}
# Flipper Devices Inc BLE OUIs (lowercase, colon-separated)
FLIPPER_OUIS = ("80:e1:26", "80:e1:27", "0c:fa:22")

# --- BLE attack signatures ("_" = one wildcard nibble) -----------------------
ATTACK_SIGNATURES = (
    ("00001812-0000-1000-8000-00805f9b34fb", "BLE_HUMAN_INTERFACE_DEVICE"),
    ("4c000719010_2055_______________", "BLE_APPLE_DEVICE_POPUP_CLOSE"),
    ("4c000f05c00____________________", "BLE_APPLE_ACTION_MODAL_LONG"),
    ("4c00071907_____________________", "BLE_APPLE_DEVICE_CONNECT"),
    ("4c0004042a0000000f05c1__604c950", "BLE_APPLE_DEVICE_SETUP"),
    ("2cfe___________________________", "BLE_ANDROID_DEVICE_CONNECT"),
    ("750042098102141503210109____01_", "BLE_SAMSUNG_BUDS_POPUP_LONG"),
    ("7500010002000101ff000043_______", "BLE_SAMSUNG_WATCH_PAIR_LONG"),
    ("0600030080_____________________", "BLE_WINDOWS_SWIFT_PAIR_SHORT"),
    ("ff006db643ce97fe427c___________", "BLE_LOVE_TOYS_SHORT_DISTANCE"),
)
ATTACK_TYPES = tuple(dict.fromkeys(attack_type for _, attack_type in ATTACK_SIGNATURES))

# --- Home Assistant bus events -----------------------------------------------
EVENT_FLIPPER_DETECTED = "wall_of_flippers_flipper_detected"
EVENT_ATTACK_DETECTED = "wall_of_flippers_attack_detected"

# --- Dispatcher signals (formatted with the entry_id at runtime) -------------
SIGNAL_UPDATE = "wall_of_flippers_update_{}"
SIGNAL_NEW_FLIPPER = "wall_of_flippers_new_flipper_{}"
SIGNAL_ATTACK = "wall_of_flippers_attack_{}"

# --- Options -----------------------------------------------------------------
CONF_RSSI_FLOOR = "rssi_floor"
CONF_STALE_TIMEOUT = "stale_timeout"
CONF_ATTACK_WINDOW = "attack_window"
CONF_ENABLE_ATTACK_DETECTION = "enable_attack_detection"
CONF_RATE_LIMIT_COUNT = "rate_limit_count"
CONF_RATE_LIMIT_WINDOW = "rate_limit_window"

DEFAULT_RSSI_FLOOR = -90
DEFAULT_STALE_TIMEOUT = 300
DEFAULT_ATTACK_WINDOW = 60
DEFAULT_ENABLE_ATTACK_DETECTION = True
DEFAULT_RATE_LIMIT_COUNT = 3
DEFAULT_RATE_LIMIT_WINDOW = 5
```

- [ ] **Step 2: Write `manifest.json`**

```json
{
  "domain": "wall_of_flippers",
  "name": "Wall of Flippers",
  "codeowners": ["@REPLACE_ME"],
  "config_flow": true,
  "dependencies": ["bluetooth"],
  "documentation": "https://github.com/REPLACE_ME/hassio-wall-of-flippers",
  "integration_type": "hub",
  "iot_class": "local_push",
  "issue_tracker": "https://github.com/REPLACE_ME/hassio-wall-of-flippers/issues",
  "requirements": [],
  "version": "0.1.0"
}
```

- [ ] **Step 3: Write `hacs.json`**

```json
{
  "name": "Wall of Flippers",
  "content_in_root": false,
  "render_readme": true,
  "homeassistant": "2024.8.0"
}
```

- [ ] **Step 4: Write temporary minimal `__init__.py`** (replaced in Task 4 — allows imports to resolve early)

```python
"""The Wall of Flippers integration."""
```

- [ ] **Step 5: Write `requirements-test.txt`**

```text
pytest-homeassistant-custom-component
```

- [ ] **Step 6: Write `tests/__init__.py`** (empty file)

```python
```

- [ ] **Step 7: Write `tests/conftest.py`**

```python
"""Fixtures for Wall of Flippers tests."""
import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable loading custom integrations in all tests."""
    yield
```

- [ ] **Step 8: Write `tests/test_const.py`**

```python
"""Sanity checks for constants."""
from custom_components.wall_of_flippers import const


def test_attack_types_are_unique_and_nonempty():
    assert len(const.ATTACK_TYPES) == len(set(const.ATTACK_TYPES))
    assert all(const.ATTACK_TYPES)


def test_flipper_variants_use_base_suffix():
    assert all(uuid.endswith(const.BASE_UUID_SUFFIX) for uuid in const.FLIPPER_VARIANTS)
```

- [ ] **Step 9: Write `.github/workflows/validate.yml`**

```yaml
name: Validate

on:
  push:
  pull_request:
  schedule:
    - cron: "0 0 * * *"

jobs:
  hassfest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: home-assistant/actions/hassfest@master

  hacs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hacs/action@main
        with:
          category: integration

  tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements-test.txt
      - run: pytest
```

- [ ] **Step 10: Run the const test**

Run: `pip install -r requirements-test.txt && pytest tests/test_const.py -v`
Expected: PASS (2 passed)

- [ ] **Step 11: Commit**

```bash
git add custom_components hacs.json requirements-test.txt tests .github
git commit -m "feat: scaffold wall_of_flippers integration with constants and CI"
```

---

### Task 2: Detection engine (`detection.py`)

**Files:**
- Create: `custom_components/wall_of_flippers/detection.py`
- Test: `tests/test_detection.py`

**Interfaces:**
- Consumes: constants from `const.py`.
- Produces:
  - `@dataclass(frozen=True) FlipperInfo(address: str, name: str, variant: str, detection_type: str, uid: str, rssi: int)`
  - `@dataclass(frozen=True) AttackHit(attack_type: str, matched_signature: str, address: str, rssi: int)`
  - `identify_flipper(info) -> FlipperInfo | None`
  - `match_attacks(info) -> list[AttackHit]`
  - where `info` is any object exposing `.name: str | None`, `.address: str`, `.rssi: int | None`, `.service_uuids: list[str]`, `.service_data: dict[str, bytes]`, `.manufacturer_data: dict[int, bytes]` (i.e. `BluetoothServiceInfoBleak`).

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the pure detection engine."""
from dataclasses import dataclass, field

from custom_components.wall_of_flippers.detection import (
    AttackHit,
    FlipperInfo,
    identify_flipper,
    match_attacks,
)


@dataclass
class FakeInfo:
    """Minimal stand-in for BluetoothServiceInfoBleak."""

    address: str = "aa:bb:cc:dd:ee:ff"
    name: str | None = None
    rssi: int | None = -50
    service_uuids: list = field(default_factory=list)
    service_data: dict = field(default_factory=dict)
    manufacturer_data: dict = field(default_factory=dict)


BLACK = "00003081-0000-1000-8000-00805f9b34fb"
WHITE = "00003082-0000-1000-8000-00805f9b34fb"
SPOOF = "00003088-0000-1000-8000-00805f9b34fb"


def test_identifies_white_flipper_by_name():
    info = FakeInfo(name="Flipper Zilch", service_uuids=[WHITE])
    result = identify_flipper(info)
    assert result == FlipperInfo(
        address="aa:bb:cc:dd:ee:ff",
        name="Flipper Zilch",
        variant="White",
        detection_type="Name",
        uid=WHITE,
        rssi=-50,
    )


def test_identifies_flipper_by_oui_when_name_generic():
    info = FakeInfo(address="80:E1:26:00:11:22", name="node", service_uuids=[BLACK])
    result = identify_flipper(info)
    assert result.variant == "Black"
    assert result.detection_type == "Address"
    assert result.address == "80:e1:26:00:11:22"


def test_identifies_flipper_by_identifier_only():
    info = FakeInfo(name="beacon", service_uuids=[BLACK])
    assert identify_flipper(info).detection_type == "Identifier"


def test_spoofed_variant_uuid():
    info = FakeInfo(name="beacon", service_uuids=[SPOOF])
    result = identify_flipper(info)
    assert result.variant == "Spoofed/Unknown"


def test_non_flipper_returns_none():
    info = FakeInfo(name="Flipper Fake", service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"])
    assert identify_flipper(info) is None


def test_matches_apple_popup_close_from_manufacturer_data():
    info = FakeInfo(manufacturer_data={0x004C: bytes.fromhex("0719010f2055aabbccddeeff0011223344")})
    hits = match_attacks(info)
    assert AttackHit(
        attack_type="BLE_APPLE_DEVICE_POPUP_CLOSE",
        matched_signature="4c000719010_2055_______________",
        address="aa:bb:cc:dd:ee:ff",
        rssi=-50,
    ) in hits


def test_matches_windows_swift_pair_from_manufacturer_data():
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbccddeeff")})
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_WINDOWS_SWIFT_PAIR_SHORT" in types


def test_matches_android_fast_pair_from_service_data():
    info = FakeInfo(service_data={"0000fe2c-0000-1000-8000-00805f9b34fb": bytes.fromhex("aabbcc")})
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_ANDROID_DEVICE_CONNECT" in types


def test_matches_hid_from_service_uuid():
    info = FakeInfo(service_uuids=["00001812-0000-1000-8000-00805f9b34fb"])
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_HUMAN_INTERFACE_DEVICE" in types


def test_benign_advertisement_no_attack():
    info = FakeInfo(manufacturer_data={0x004C: bytes.fromhex("0215")})
    assert match_attacks(info) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_detection.py -v`
Expected: FAIL with `ModuleNotFoundError` / `ImportError` (detection.py not present)

- [ ] **Step 3: Write `detection.py`**

```python
"""Pure BLE detection logic for Wall of Flippers.

This module must not import homeassistant.* so it can be unit-tested in
isolation. `info` is any object exposing the BluetoothServiceInfoBleak
attributes used below.
"""
from __future__ import annotations

from dataclasses import dataclass

from .const import (
    ATTACK_SIGNATURES,
    BASE_UUID_SUFFIX,
    FLIPPER_OUIS,
    FLIPPER_UUID_PREFIX,
    FLIPPER_VARIANTS,
)


@dataclass(frozen=True)
class FlipperInfo:
    """A detected Flipper Zero device."""

    address: str
    name: str
    variant: str
    detection_type: str
    uid: str
    rssi: int


@dataclass(frozen=True)
class AttackHit:
    """A single matched BLE attack signature."""

    attack_type: str
    matched_signature: str
    address: str
    rssi: int


def _short_uuid_le(uuid: str) -> str | None:
    """Return little-endian 16-bit hex for a base-suffixed UUID, else None."""
    uuid = uuid.lower()
    if uuid.startswith("0000") and uuid.endswith(BASE_UUID_SUFFIX):
        short = uuid[4:8]  # e.g. "fe2c"
        return short[2:4] + short[0:2]  # little-endian swap -> "2cfe"
    return None


def _candidate_hex_strings(info) -> list[str]:
    """Reconstruct hex candidate strings from an advertisement."""
    candidates: list[str] = []
    for company_id, data in (info.manufacturer_data or {}).items():
        candidates.append(company_id.to_bytes(2, "little").hex() + data.hex())
    for uuid, data in (info.service_data or {}).items():
        short = _short_uuid_le(uuid)
        if short is not None:
            candidates.append(short + data.hex())
        candidates.append(uuid.lower().replace("-", "") + data.hex())
    for uuid in info.service_uuids or []:
        candidates.append(uuid.lower())
    return candidates


def _signature_matches(candidate: str, signature: str) -> bool:
    """Wildcard match: '_' matches any one nibble; candidate must be >= length."""
    candidate = candidate.lower()
    signature = signature.lower()
    if len(candidate) < len(signature):
        return False
    return all(s == "_" or s == c for c, s in zip(candidate, signature))


def identify_flipper(info) -> FlipperInfo | None:
    """Classify an advertisement as a Flipper Zero, or return None."""
    variant: str | None = None
    uid = "unknown"
    for raw in info.service_uuids or []:
        service_uuid = raw.lower()
        if service_uuid in FLIPPER_VARIANTS:
            variant, uid = FLIPPER_VARIANTS[service_uuid], service_uuid
            break
        if service_uuid.startswith(FLIPPER_UUID_PREFIX) and service_uuid.endswith(
            BASE_UUID_SUFFIX
        ):
            variant, uid = "Spoofed/Unknown", service_uuid
    if variant is None:
        return None

    name = info.name or ""
    address = info.address.lower()
    if name.lower().startswith("flipper"):
        detection_type = "Name"
    elif address.startswith(FLIPPER_OUIS):
        detection_type = "Address"
    else:
        detection_type = "Identifier"

    rssi = info.rssi if info.rssi is not None else 0
    return FlipperInfo(address, name, variant, detection_type, uid, rssi)


def match_attacks(info) -> list[AttackHit]:
    """Return all attack signatures matched by the advertisement."""
    candidates = _candidate_hex_strings(info)
    address = info.address.lower()
    rssi = info.rssi if info.rssi is not None else 0
    hits: list[AttackHit] = []
    seen: set[str] = set()
    for signature, attack_type in ATTACK_SIGNATURES:
        if attack_type in seen:
            continue
        if any(_signature_matches(c, signature) for c in candidates):
            hits.append(AttackHit(attack_type, signature, address, rssi))
            seen.add(attack_type)
    return hits
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_detection.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add custom_components/wall_of_flippers/detection.py tests/test_detection.py
git commit -m "feat: add pure BLE detection engine for flippers and attacks"
```

---

### Task 3: Runtime detector (`detector.py`)

**Files:**
- Create: `custom_components/wall_of_flippers/detector.py`
- Test: `tests/test_detector.py`

**Interfaces:**
- Consumes: `identify_flipper`, `match_attacks`, `FlipperInfo`, `AttackHit` from `detection.py`; `CONF_*`/`DEFAULT_*` from `const.py`.
- Produces:
  - `class WallOfFlippersDetector(options: dict, *, on_change=None, on_new_flipper=None, on_attack=None)`
  - `process(self, info, now: float) -> None` — main entry; `now` is epoch seconds (float).
  - `expire(self, now: float) -> None` — drop stale flippers / old attacks.
  - `live_flippers: dict[str, dict]` — MAC → `{"info": FlipperInfo, "first_seen": float, "last_seen": float, "source": str | None}`.
  - properties: `flipper_count -> int`, `has_live_flipper -> bool`, `last_attack_type -> str | None`, `attack_count_last_minute(now) -> int`, `attack_active(now) -> bool`.
  - callbacks fire as: `on_new_flipper(FlipperInfo, source)`, `on_change()`, `on_attack(AttackHit, source)`.

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the runtime detector state machine."""
from dataclasses import dataclass, field

import pytest

from custom_components.wall_of_flippers.const import (
    CONF_ATTACK_WINDOW,
    CONF_ENABLE_ATTACK_DETECTION,
    CONF_RATE_LIMIT_COUNT,
    CONF_RATE_LIMIT_WINDOW,
    CONF_RSSI_FLOOR,
    CONF_STALE_TIMEOUT,
)
from custom_components.wall_of_flippers.detector import WallOfFlippersDetector


@dataclass
class FakeInfo:
    address: str = "aa:bb:cc:dd:ee:ff"
    name: str | None = None
    rssi: int | None = -50
    source: str | None = "proxy-1"
    service_uuids: list = field(default_factory=list)
    service_data: dict = field(default_factory=dict)
    manufacturer_data: dict = field(default_factory=dict)


BLACK = "00003081-0000-1000-8000-00805f9b34fb"

OPTIONS = {
    CONF_RSSI_FLOOR: -90,
    CONF_STALE_TIMEOUT: 300,
    CONF_ATTACK_WINDOW: 60,
    CONF_ENABLE_ATTACK_DETECTION: True,
    CONF_RATE_LIMIT_COUNT: 3,
    CONF_RATE_LIMIT_WINDOW: 5,
}


def _flipper(address, name="Flipper Zilch"):
    return FakeInfo(address=address, name=name, service_uuids=[BLACK])


def test_registers_new_flipper_and_fires_callbacks():
    new, changes = [], []
    det = WallOfFlippersDetector(
        OPTIONS,
        on_new_flipper=lambda fi, src: new.append((fi, src)),
        on_change=lambda: changes.append(True),
    )
    det.process(_flipper("11:22:33:44:55:66"), now=1000.0)
    assert det.flipper_count == 1
    assert det.has_live_flipper is True
    assert len(new) == 1
    assert new[0][1] == "proxy-1"
    assert changes  # on_change fired


def test_rssi_floor_ignores_weak_signals():
    det = WallOfFlippersDetector(OPTIONS)
    info = _flipper("11:22:33:44:55:66")
    info.rssi = -120
    det.process(info, now=1000.0)
    assert det.flipper_count == 0


def test_rate_limit_flags_spoof_flood():
    new = []
    det = WallOfFlippersDetector(OPTIONS, on_new_flipper=lambda fi, src: new.append(fi))
    # 3 distinct new flippers within the 5s window -> becomes rate-limited;
    # the 3rd+ are dropped as suspected spoof-flood.
    det.process(_flipper("00:00:00:00:00:01"), now=1000.0)
    det.process(_flipper("00:00:00:00:00:02"), now=1001.0)
    det.process(_flipper("00:00:00:00:00:03"), now=1002.0)
    det.process(_flipper("00:00:00:00:00:04"), now=1003.0)
    assert det.flipper_count <= 2
    assert det.rate_limited is True


def test_expire_removes_stale_flipper():
    changes = []
    det = WallOfFlippersDetector(OPTIONS, on_change=lambda: changes.append(True))
    det.process(_flipper("11:22:33:44:55:66"), now=1000.0)
    det.expire(now=1000.0 + 301)
    assert det.flipper_count == 0
    assert det.has_live_flipper is False


def test_attack_detection_and_window():
    hits = []
    det = WallOfFlippersDetector(OPTIONS, on_attack=lambda hit, src: hits.append(hit))
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    assert det.attack_active(now=2000.0) is True
    assert det.last_attack_type == "BLE_WINDOWS_SWIFT_PAIR_SHORT"
    assert det.attack_count_last_minute(now=2000.0) == 1
    assert len(hits) == 1
    # after the window, no longer active
    assert det.attack_active(now=2000.0 + 61) is False


def test_attack_detection_can_be_disabled():
    opts = dict(OPTIONS, **{CONF_ENABLE_ATTACK_DETECTION: False})
    det = WallOfFlippersDetector(opts)
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    assert det.attack_active(now=2000.0) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_detector.py -v`
Expected: FAIL with `ImportError` (detector.py not present)

- [ ] **Step 3: Write `detector.py`**

```python
"""Runtime state for Wall of Flippers detections."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any

from .const import (
    CONF_ATTACK_WINDOW,
    CONF_ENABLE_ATTACK_DETECTION,
    CONF_RATE_LIMIT_COUNT,
    CONF_RATE_LIMIT_WINDOW,
    CONF_RSSI_FLOOR,
    CONF_STALE_TIMEOUT,
    DEFAULT_ATTACK_WINDOW,
    DEFAULT_ENABLE_ATTACK_DETECTION,
    DEFAULT_RATE_LIMIT_COUNT,
    DEFAULT_RATE_LIMIT_WINDOW,
    DEFAULT_RSSI_FLOOR,
    DEFAULT_STALE_TIMEOUT,
)
from .detection import AttackHit, FlipperInfo, identify_flipper, match_attacks


class WallOfFlippersDetector:
    """Holds live flipper/attack state and pushes updates via callbacks."""

    def __init__(
        self,
        options: dict[str, Any],
        *,
        on_change: Callable[[], None] | None = None,
        on_new_flipper: Callable[[FlipperInfo, str | None], None] | None = None,
        on_attack: Callable[[AttackHit, str | None], None] | None = None,
    ) -> None:
        self._options = options
        self._on_change = on_change
        self._on_new_flipper = on_new_flipper
        self._on_attack = on_attack

        self.live_flippers: dict[str, dict[str, Any]] = {}
        self._attacks: deque[tuple[float, AttackHit]] = deque()
        self._new_flipper_times: deque[float] = deque()
        self._rate_limited_until = 0.0
        self._last_attack_type: str | None = None

    # --- options helpers -----------------------------------------------------
    def _opt(self, key: str, default: Any) -> Any:
        value = self._options.get(key, default)
        return default if value is None else value

    # --- main entry ----------------------------------------------------------
    def process(self, info, now: float) -> None:
        """Process a single advertisement."""
        rssi = info.rssi if info.rssi is not None else 0
        if rssi < self._opt(CONF_RSSI_FLOOR, DEFAULT_RSSI_FLOOR):
            return

        flipper = identify_flipper(info)
        if flipper is not None:
            self._handle_flipper(flipper, getattr(info, "source", None), now)

        if self._opt(CONF_ENABLE_ATTACK_DETECTION, DEFAULT_ENABLE_ATTACK_DETECTION):
            for hit in match_attacks(info):
                self._handle_attack(hit, getattr(info, "source", None), now)

    def _handle_flipper(self, flipper: FlipperInfo, source: str | None, now: float) -> None:
        is_new = flipper.address not in self.live_flippers
        if is_new:
            window = self._opt(CONF_RATE_LIMIT_WINDOW, DEFAULT_RATE_LIMIT_WINDOW)
            count = self._opt(CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT)
            self._new_flipper_times.append(now)
            while self._new_flipper_times and now - self._new_flipper_times[0] > window:
                self._new_flipper_times.popleft()
            if len(self._new_flipper_times) >= count:
                self._rate_limited_until = now + window
            if now < self._rate_limited_until:
                # Suspected spoof-flood: do not trust this device.
                return
            self.live_flippers[flipper.address] = {
                "info": flipper,
                "first_seen": now,
                "last_seen": now,
                "source": source,
            }
            if self._on_new_flipper is not None:
                self._on_new_flipper(flipper, source)
        else:
            record = self.live_flippers[flipper.address]
            record["info"] = flipper
            record["last_seen"] = now
            record["source"] = source
        self._changed()

    def _handle_attack(self, hit: AttackHit, source: str | None, now: float) -> None:
        self._attacks.append((now, hit))
        self._last_attack_type = hit.attack_type
        if self._on_attack is not None:
            self._on_attack(hit, source)
        self._changed()

    # --- expiry --------------------------------------------------------------
    def expire(self, now: float) -> None:
        """Remove stale flippers and drop attacks older than one minute."""
        stale = self._opt(CONF_STALE_TIMEOUT, DEFAULT_STALE_TIMEOUT)
        removed = [
            mac
            for mac, rec in self.live_flippers.items()
            if now - rec["last_seen"] > stale
        ]
        for mac in removed:
            del self.live_flippers[mac]
        while self._attacks and now - self._attacks[0][0] > 60:
            self._attacks.popleft()
        if removed:
            self._changed()

    def _changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    # --- read-only state -----------------------------------------------------
    @property
    def rate_limited(self) -> bool:
        return bool(self._rate_limited_until) and any(
            True for _ in self._new_flipper_times
        ) and self._rate_limited_until > 0 and self._new_flipper_times and True

    @property
    def flipper_count(self) -> int:
        return len(self.live_flippers)

    @property
    def has_live_flipper(self) -> bool:
        return bool(self.live_flippers)

    @property
    def last_attack_type(self) -> str | None:
        return self._last_attack_type

    def attack_count_last_minute(self, now: float) -> int:
        return sum(1 for ts, _ in self._attacks if now - ts <= 60)

    def attack_active(self, now: float) -> bool:
        window = self._opt(CONF_ATTACK_WINDOW, DEFAULT_ATTACK_WINDOW)
        return any(now - ts <= window for ts, _ in self._attacks)
```

- [ ] **Step 4: Simplify the `rate_limited` property**

Replace the `rate_limited` property body (it was written awkwardly) with:

```python
    @property
    def rate_limited(self) -> bool:
        return len(self._new_flipper_times) >= self._opt(
            CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_detector.py -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add custom_components/wall_of_flippers/detector.py tests/test_detector.py
git commit -m "feat: add runtime detector with rate-limit and expiry"
```

---

### Task 4: Integration setup, config flow, and translations

**Files:**
- Modify (replace): `custom_components/wall_of_flippers/__init__.py`
- Create: `custom_components/wall_of_flippers/config_flow.py`
- Create: `custom_components/wall_of_flippers/strings.json`
- Create: `custom_components/wall_of_flippers/translations/en.json`
- Test: `tests/test_config_flow.py`
- Test: `tests/test_init.py`

**Interfaces:**
- Consumes: `WallOfFlippersDetector`, all `const.py` symbols.
- Produces:
  - `type WallOfFlippersConfigEntry = ConfigEntry[WallOfFlippersDetector]` (detector stored in `entry.runtime_data`).
  - `async_setup_entry(hass, entry) -> bool`, `async_unload_entry(hass, entry) -> bool`.
  - Config flow domain `wall_of_flippers`, single instance, with an options flow exposing all `CONF_*` keys.

- [ ] **Step 1: Write the failing config-flow test**

```python
"""Config flow tests."""
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.wall_of_flippers.const import DOMAIN


async def test_user_flow_creates_single_entry(hass: HomeAssistant):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Wall of Flippers"


async def test_single_instance_only(hass: HomeAssistant):
    await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_config_flow.py -v`
Expected: FAIL (config_flow not present / flow not registered)

- [ ] **Step 3: Write `config_flow.py`**

```python
"""Config and options flow for Wall of Flippers."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from .const import (
    CONF_ATTACK_WINDOW,
    CONF_ENABLE_ATTACK_DETECTION,
    CONF_RATE_LIMIT_COUNT,
    CONF_RATE_LIMIT_WINDOW,
    CONF_RSSI_FLOOR,
    CONF_STALE_TIMEOUT,
    DEFAULT_ATTACK_WINDOW,
    DEFAULT_ENABLE_ATTACK_DETECTION,
    DEFAULT_RATE_LIMIT_COUNT,
    DEFAULT_RATE_LIMIT_WINDOW,
    DEFAULT_RSSI_FLOOR,
    DEFAULT_STALE_TIMEOUT,
    DOMAIN,
)


class WallOfFlippersConfigFlow(ConfigFlow, domain=DOMAIN):
    """Single-instance config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        return self.async_create_entry(title="Wall of Flippers", data={})

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return WallOfFlippersOptionsFlow()


class WallOfFlippersOptionsFlow(OptionsFlow):
    """Options for tuning detection thresholds."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_RSSI_FLOOR,
                    default=options.get(CONF_RSSI_FLOOR, DEFAULT_RSSI_FLOOR),
                ): vol.All(int, vol.Range(min=-127, max=0)),
                vol.Required(
                    CONF_STALE_TIMEOUT,
                    default=options.get(CONF_STALE_TIMEOUT, DEFAULT_STALE_TIMEOUT),
                ): vol.All(int, vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_ATTACK_WINDOW,
                    default=options.get(CONF_ATTACK_WINDOW, DEFAULT_ATTACK_WINDOW),
                ): vol.All(int, vol.Range(min=5, max=600)),
                vol.Required(
                    CONF_ENABLE_ATTACK_DETECTION,
                    default=options.get(
                        CONF_ENABLE_ATTACK_DETECTION, DEFAULT_ENABLE_ATTACK_DETECTION
                    ),
                ): bool,
                vol.Required(
                    CONF_RATE_LIMIT_COUNT,
                    default=options.get(
                        CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT
                    ),
                ): vol.All(int, vol.Range(min=1, max=50)),
                vol.Required(
                    CONF_RATE_LIMIT_WINDOW,
                    default=options.get(
                        CONF_RATE_LIMIT_WINDOW, DEFAULT_RATE_LIMIT_WINDOW
                    ),
                ): vol.All(int, vol.Range(min=1, max=60)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
```

- [ ] **Step 4: Write `__init__.py`** (replacing the temporary file)

```python
"""The Wall of Flippers integration."""
from __future__ import annotations

from datetime import timedelta

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
import homeassistant.util.dt as dt_util

from .const import (
    EVENT_ATTACK_DETECTED,
    EVENT_FLIPPER_DETECTED,
    PLATFORMS,
    SIGNAL_ATTACK,
    SIGNAL_NEW_FLIPPER,
    SIGNAL_UPDATE,
)
from .detection import AttackHit, FlipperInfo
from .detector import WallOfFlippersDetector

type WallOfFlippersConfigEntry = ConfigEntry[WallOfFlippersDetector]

SCAN_INTERVAL = timedelta(seconds=15)


async def async_setup_entry(
    hass: HomeAssistant, entry: WallOfFlippersConfigEntry
) -> bool:
    """Set up Wall of Flippers from a config entry."""

    @callback
    def _on_change() -> None:
        async_dispatcher_send(hass, SIGNAL_UPDATE.format(entry.entry_id))

    @callback
    def _on_new_flipper(flipper: FlipperInfo, source: str | None) -> None:
        async_dispatcher_send(
            hass, SIGNAL_NEW_FLIPPER.format(entry.entry_id), flipper, source
        )
        hass.bus.async_fire(
            EVENT_FLIPPER_DETECTED,
            {
                "address": flipper.address,
                "name": flipper.name,
                "variant": flipper.variant,
                "detection_type": flipper.detection_type,
                "rssi": flipper.rssi,
                "source": source,
            },
        )

    @callback
    def _on_attack(hit: AttackHit, source: str | None) -> None:
        async_dispatcher_send(
            hass, SIGNAL_ATTACK.format(entry.entry_id), hit, source
        )
        hass.bus.async_fire(
            EVENT_ATTACK_DETECTED,
            {
                "attack_type": hit.attack_type,
                "matched_signature": hit.matched_signature,
                "address": hit.address,
                "rssi": hit.rssi,
                "source": source,
            },
        )

    detector = WallOfFlippersDetector(
        dict(entry.options),
        on_change=_on_change,
        on_new_flipper=_on_new_flipper,
        on_attack=_on_attack,
    )
    entry.runtime_data = detector

    @callback
    def _advertisement(
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        detector.process(service_info, now=dt_util.utcnow().timestamp())

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _advertisement,
            bluetooth.BluetoothCallbackMatcher(connectable=False),
            bluetooth.BluetoothScanningMode.PASSIVE,
        )
    )

    @callback
    def _expire(_now) -> None:
        detector.expire(dt_util.utcnow().timestamp())

    entry.async_on_unload(async_track_time_interval(hass, _expire, SCAN_INTERVAL))
    entry.async_on_unload(entry.add_update_listener(_reload_on_options))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _reload_on_options(
    hass: HomeAssistant, entry: WallOfFlippersConfigEntry
) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(
    hass: HomeAssistant, entry: WallOfFlippersConfigEntry
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
```

- [ ] **Step 5: Write `strings.json`**

```json
{
  "config": {
    "step": {
      "user": {
        "description": "Wall of Flippers listens to BLE advertisements (including those relayed by Bluetooth proxies) to detect nearby Flipper Zero devices and BLE spam attacks."
      }
    },
    "abort": {
      "single_instance_allowed": "Wall of Flippers is already configured. Only one instance is allowed."
    }
  },
  "options": {
    "step": {
      "init": {
        "title": "Wall of Flippers options",
        "data": {
          "rssi_floor": "Minimum RSSI (dBm) to consider",
          "stale_timeout": "Seconds before a Flipper is considered away",
          "attack_window": "Seconds an attack stays flagged as active",
          "enable_attack_detection": "Enable BLE attack detection",
          "rate_limit_count": "New Flippers per window before spoof-flood is assumed",
          "rate_limit_window": "Rate-limit window (seconds)"
        }
      }
    }
  }
}
```

- [ ] **Step 6: Write `translations/en.json`** (identical content to `strings.json`)

```json
{
  "config": {
    "step": {
      "user": {
        "description": "Wall of Flippers listens to BLE advertisements (including those relayed by Bluetooth proxies) to detect nearby Flipper Zero devices and BLE spam attacks."
      }
    },
    "abort": {
      "single_instance_allowed": "Wall of Flippers is already configured. Only one instance is allowed."
    }
  },
  "options": {
    "step": {
      "init": {
        "title": "Wall of Flippers options",
        "data": {
          "rssi_floor": "Minimum RSSI (dBm) to consider",
          "stale_timeout": "Seconds before a Flipper is considered away",
          "attack_window": "Seconds an attack stays flagged as active",
          "enable_attack_detection": "Enable BLE attack detection",
          "rate_limit_count": "New Flippers per window before spoof-flood is assumed",
          "rate_limit_window": "Rate-limit window (seconds)"
        }
      }
    }
  }
}
```

- [ ] **Step 7: Write `tests/test_init.py`**

```python
"""Setup / unload tests."""
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.wall_of_flippers.const import DOMAIN


async def test_setup_and_unload(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Wall of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data is not None

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED
```

- [ ] **Step 8: Run the flow + init tests**

Run: `pytest tests/test_config_flow.py tests/test_init.py -v`
Expected: PASS (all tests)

- [ ] **Step 9: Commit**

```bash
git add custom_components/wall_of_flippers/__init__.py custom_components/wall_of_flippers/config_flow.py custom_components/wall_of_flippers/strings.json custom_components/wall_of_flippers/translations tests/test_config_flow.py tests/test_init.py
git commit -m "feat: add config flow, options, and entry setup wiring"
```

---

### Task 5: Aggregate binary_sensor and sensor entities

**Files:**
- Create: `custom_components/wall_of_flippers/entity.py`
- Create: `custom_components/wall_of_flippers/binary_sensor.py`
- Create: `custom_components/wall_of_flippers/sensor.py`
- Test: `tests/test_aggregate_entities.py`

**Interfaces:**
- Consumes: `WallOfFlippersConfigEntry` / detector from `entry.runtime_data`; `SIGNAL_UPDATE`.
- Produces:
  - `entity.py`: `WallOfFlippersBaseEntity(entry)` — sets `_attr_has_entity_name`, device_info (hub device), and subscribes to `SIGNAL_UPDATE` to call `async_write_ha_state`.
  - `binary_sensor.py`: entities `Flipper Zero Detected`, `BLE Attack Detected`.
  - `sensor.py`: entities `Flippers Nearby`, `BLE Attacks per Minute`, `Last Attack Type`.

- [ ] **Step 1: Write the failing test**

```python
"""Aggregate entity tests."""
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.wall_of_flippers.const import DOMAIN


async def test_aggregate_entities_created(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Wall of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("binary_sensor.wall_of_flippers_flipper_zero_detected")
    assert hass.states.get("binary_sensor.wall_of_flippers_ble_attack_detected")
    assert hass.states.get("sensor.wall_of_flippers_flippers_nearby").state == "0"
    assert hass.states.get("sensor.wall_of_flippers_ble_attacks_per_minute")
    assert hass.states.get("sensor.wall_of_flippers_last_attack_type")
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_aggregate_entities.py -v`
Expected: FAIL (entities not created / platforms missing)

- [ ] **Step 3: Write `entity.py`**

```python
"""Shared base entity for Wall of Flippers."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity

from .const import DOMAIN, SIGNAL_UPDATE


class WallOfFlippersBaseEntity(Entity):
    """Base class wiring device info and dispatcher updates."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry) -> None:
        self._entry = entry
        self._detector = entry.runtime_data
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Wall of Flippers",
            manufacturer="Wall of Flippers",
            model="BLE Monitor",
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_UPDATE.format(self._entry.entry_id),
                self.async_write_ha_state,
            )
        )
```

- [ ] **Step 4: Write `binary_sensor.py`**

```python
"""Aggregate binary sensors for Wall of Flippers."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant
import homeassistant.util.dt as dt_util
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import WallOfFlippersBaseEntity


async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities(
        [FlipperDetectedBinarySensor(entry), AttackDetectedBinarySensor(entry)]
    )


class FlipperDetectedBinarySensor(WallOfFlippersBaseEntity, BinarySensorEntity):
    _attr_translation_key = "flipper_detected"
    _attr_name = "Flipper Zero Detected"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_flipper_detected"

    @property
    def is_on(self) -> bool:
        return self._detector.has_live_flipper


class AttackDetectedBinarySensor(WallOfFlippersBaseEntity, BinarySensorEntity):
    _attr_name = "BLE Attack Detected"
    _attr_device_class = BinarySensorDeviceClass.SAFETY

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_attack_detected"

    @property
    def is_on(self) -> bool:
        return self._detector.attack_active(dt_util.utcnow().timestamp())
```

- [ ] **Step 5: Write `sensor.py`**

```python
"""Aggregate sensors for Wall of Flippers."""
from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
import homeassistant.util.dt as dt_util
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import WallOfFlippersBaseEntity


async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities(
        [
            FlippersNearbySensor(entry),
            AttacksPerMinuteSensor(entry),
            LastAttackTypeSensor(entry),
        ]
    )


class FlippersNearbySensor(WallOfFlippersBaseEntity, SensorEntity):
    _attr_name = "Flippers Nearby"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "flippers"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_flippers_nearby"

    @property
    def native_value(self) -> int:
        return self._detector.flipper_count


class AttacksPerMinuteSensor(WallOfFlippersBaseEntity, SensorEntity):
    _attr_name = "BLE Attacks per Minute"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "attacks/min"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_attacks_per_minute"

    @property
    def native_value(self) -> int:
        return self._detector.attack_count_last_minute(dt_util.utcnow().timestamp())


class LastAttackTypeSensor(WallOfFlippersBaseEntity, SensorEntity):
    _attr_name = "Last Attack Type"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_last_attack_type"

    @property
    def native_value(self) -> str:
        return self._detector.last_attack_type or "none"
```

- [ ] **Step 6: Run the aggregate entity test**

Run: `pytest tests/test_aggregate_entities.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add custom_components/wall_of_flippers/entity.py custom_components/wall_of_flippers/binary_sensor.py custom_components/wall_of_flippers/sensor.py tests/test_aggregate_entities.py
git commit -m "feat: add aggregate binary_sensor and sensor entities"
```

---

### Task 6: Dynamic per-Flipper device_tracker

**Files:**
- Create: `custom_components/wall_of_flippers/device_tracker.py`
- Test: `tests/test_device_tracker.py`

**Interfaces:**
- Consumes: `SIGNAL_NEW_FLIPPER` (fires `(FlipperInfo, source)`), `SIGNAL_UPDATE`, detector state.
- Produces: one `WallOfFlippersTracker` per discovered MAC, created lazily on `SIGNAL_NEW_FLIPPER`.

- [ ] **Step 1: Write the failing test**

```python
"""Dynamic device_tracker tests."""
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.wall_of_flippers.const import DOMAIN


@dataclass
class FakeInfo:
    address: str = "11:22:33:44:55:66"
    name: str | None = "Flipper Zilch"
    rssi: int | None = -40
    source: str | None = "proxy-1"
    service_uuids: list = field(default_factory=lambda: ["00003081-0000-1000-8000-00805f9b34fb"])
    service_data: dict = field(default_factory=dict)
    manufacturer_data: dict = field(default_factory=dict)


async def test_device_tracker_created_on_detection(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Wall of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    entry.runtime_data.process(FakeInfo(), now=1000.0)
    await hass.async_block_till_done()

    state = hass.states.get("device_tracker.wall_of_flippers_flipper_112233445566")
    assert state is not None
    assert state.attributes["variant"] == "Black"
    assert state.attributes["detection_type"] == "Name"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_device_tracker.py -v`
Expected: FAIL (no device_tracker created)

- [ ] **Step 3: Write `device_tracker.py`**

```python
"""Dynamic per-Flipper device trackers."""
from __future__ import annotations

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import BaseTrackerEntity
from homeassistant.core import HomeAssistant, callback
import homeassistant.util.dt as dt_util
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN, SIGNAL_NEW_FLIPPER, SIGNAL_UPDATE
from .detection import FlipperInfo


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    known: set[str] = set()

    @callback
    def _add(flipper: FlipperInfo, source: str | None) -> None:
        if flipper.address in known:
            return
        known.add(flipper.address)
        async_add_entities([WallOfFlippersTracker(entry, flipper.address)])

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, SIGNAL_NEW_FLIPPER.format(entry.entry_id), _add
        )
    )


class WallOfFlippersTracker(BaseTrackerEntity, RestoreEntity):
    """Tracks a single Flipper by MAC address."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry, address: str) -> None:
        self._entry = entry
        self._detector = entry.runtime_data
        self._address = address
        slug = address.replace(":", "")
        self._attr_unique_id = f"{entry.entry_id}_{address}"
        self._attr_name = f"Flipper {slug}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry.entry_id}_{address}")},
            name=f"Flipper {slug}",
            manufacturer="Flipper Devices Inc",
            model="Flipper Zero",
            via_device=(DOMAIN, entry.entry_id),
        )

    @property
    def source_type(self) -> SourceType:
        return SourceType.BLUETOOTH_LE

    def _record(self) -> dict | None:
        return self._detector.live_flippers.get(self._address)

    @property
    def state(self) -> str:
        return "home" if self._record() is not None else "not_home"

    @property
    def extra_state_attributes(self) -> dict:
        record = self._record()
        if record is None:
            return {}
        info: FlipperInfo = record["info"]
        return {
            "variant": info.variant,
            "rssi": info.rssi,
            "detection_type": info.detection_type,
            "name": info.name,
            "uid": info.uid,
            "source": record.get("source"),
            "first_seen": dt_util.utc_from_timestamp(record["first_seen"]).isoformat(),
            "last_seen": dt_util.utc_from_timestamp(record["last_seen"]).isoformat(),
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_UPDATE.format(self._entry.entry_id),
                self.async_write_ha_state,
            )
        )
```

- [ ] **Step 4: Run the device_tracker test**

Run: `pytest tests/test_device_tracker.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add custom_components/wall_of_flippers/device_tracker.py tests/test_device_tracker.py
git commit -m "feat: add dynamic per-flipper device_tracker entities"
```

---

### Task 7: BLE Attack event entity

**Files:**
- Create: `custom_components/wall_of_flippers/event.py`
- Test: `tests/test_event.py`

**Interfaces:**
- Consumes: `SIGNAL_ATTACK` (fires `(AttackHit, source)`), `ATTACK_TYPES`.
- Produces: one `BLE Attack` event entity with `event_types=ATTACK_TYPES`.

- [ ] **Step 1: Write the failing test**

```python
"""Event entity tests."""
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.wall_of_flippers.const import DOMAIN


@dataclass
class FakeInfo:
    address: str = "aa:bb:cc:dd:ee:ff"
    name: str | None = None
    rssi: int | None = -40
    source: str | None = "proxy-1"
    service_uuids: list = field(default_factory=list)
    service_data: dict = field(default_factory=dict)
    manufacturer_data: dict = field(
        default_factory=lambda: {0x0006: bytes.fromhex("030080aabbcc")}
    )


async def test_attack_event_fires(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Wall of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("event.wall_of_flippers_ble_attack").state == "unknown"

    entry.runtime_data.process(FakeInfo(), now=2000.0)
    await hass.async_block_till_done()

    state = hass.states.get("event.wall_of_flippers_ble_attack")
    assert state.attributes["event_type"] == "BLE_WINDOWS_SWIFT_PAIR_SHORT"
    assert state.attributes["address"] == "aa:bb:cc:dd:ee:ff"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_event.py -v`
Expected: FAIL (no event entity)

- [ ] **Step 3: Write `event.py`**

```python
"""BLE attack event entity."""
from __future__ import annotations

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import ATTACK_TYPES, DOMAIN, SIGNAL_ATTACK
from .detection import AttackHit


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([BleAttackEvent(entry)])


class BleAttackEvent(EventEntity):
    """Fires whenever a BLE attack signature is matched."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_name = "BLE Attack"
    _attr_device_class = EventDeviceClass.MOTION
    _attr_event_types = list(ATTACK_TYPES)

    def __init__(self, entry) -> None:
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_ble_attack"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Wall of Flippers",
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_ATTACK.format(self._entry.entry_id), self._on_attack
            )
        )

    @callback
    def _on_attack(self, hit: AttackHit, source: str | None) -> None:
        self._trigger_event(
            hit.attack_type,
            {
                "matched_signature": hit.matched_signature,
                "address": hit.address,
                "rssi": hit.rssi,
                "source": source,
            },
        )
        self.async_write_ha_state()
```

- [ ] **Step 4: Run the event test**

Run: `pytest tests/test_event.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add custom_components/wall_of_flippers/event.py tests/test_event.py
git commit -m "feat: add BLE attack event entity"
```

---

### Task 8: README, full test run, and validation polish

**Files:**
- Create: `README.md`
- Create: `LICENSE` (MIT)

**Interfaces:**
- Consumes: everything.
- Produces: user-facing documentation and a clean full test run.

- [ ] **Step 1: Write `README.md`**

````markdown
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

## Disclaimer

Detection is heuristic and signature-based; false positives/negatives are possible.
This tool is passive and detection-only.
````

- [ ] **Step 2: Write `LICENSE`** (MIT, current year, placeholder holder)

```text
MIT License

Copyright (c) 2026 REPLACE_ME

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Run the full test suite**

Run: `pytest -v`
Expected: PASS (all tests from Tasks 1–7)

- [ ] **Step 4: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: add README and license"
```

---

## Self-Review Notes

- **Spec coverage:** §2 proxies → Task 4 broad passive callback; §3 detection → Task 2; §4 runtime/rate-limit/expiry → Task 3; §5 aggregate/dynamic/event/bus → Tasks 5/6/7 + Task 4 bus fires; §6 config/options → Task 4; §7 manifest → Task 1; §8 layout → all tasks; §9 testing → tests per task + CI in Task 1. All covered.
- **Placeholder scan:** Only intentional `REPLACE_ME` repo/owner placeholders remain (called out in Global Constraints).
- **Type consistency:** `FlipperInfo`/`AttackHit` field names and `WallOfFlippersDetector` method/property names are used identically across Tasks 3–7. `SIGNAL_*` constants are `.format(entry_id)` everywhere. `entry.runtime_data` is the detector everywhere.
