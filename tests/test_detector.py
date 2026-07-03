"""Tests for the runtime detector state machine."""
from dataclasses import dataclass, field

from custom_components.home_of_flippers.const import (
    CONF_ATTACK_WINDOW,
    CONF_ENABLE_ATTACK_DETECTION,
    CONF_RATE_LIMIT_COUNT,
    CONF_RATE_LIMIT_WINDOW,
    CONF_RSSI_FLOOR,
    CONF_STALE_TIMEOUT,
)
from custom_components.home_of_flippers.detector import HomeOfFlippersDetector


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
    det = HomeOfFlippersDetector(
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
    det = HomeOfFlippersDetector(OPTIONS)
    info = _flipper("11:22:33:44:55:66")
    info.rssi = -120
    det.process(info, now=1000.0)
    assert det.flipper_count == 0


def test_rate_limit_flags_spoof_flood():
    new = []
    det = HomeOfFlippersDetector(OPTIONS, on_new_flipper=lambda fi, src: new.append(fi))
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
    det = HomeOfFlippersDetector(OPTIONS, on_change=lambda: changes.append(True))
    det.process(_flipper("11:22:33:44:55:66"), now=1000.0)
    det.expire(now=1000.0 + 301)
    assert det.flipper_count == 0
    assert det.has_live_flipper is False


def test_attack_detection_and_window():
    hits = []
    det = HomeOfFlippersDetector(OPTIONS, on_attack=lambda hit, src: hits.append(hit))
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    assert det.attack_active(now=2000.0) is True
    assert det.last_attack_type == "BLE_WINDOWS_SWIFT_PAIR_SHORT"
    assert det.attack_count_last_minute(now=2000.0) == 1
    assert len(hits) == 1
    # after the window, no longer active
    assert det.attack_active(now=2000.0 + 61) is False


def test_repeat_sighting_does_not_rewrite_state():
    # A present Flipper re-advertises constantly; only the first sighting
    # (which changes the count) should write aggregate entity state.
    changes = []
    det = HomeOfFlippersDetector(OPTIONS, on_change=lambda: changes.append(True))
    flipper = _flipper("11:22:33:44:55:66")
    det.process(flipper, now=1000.0)
    det.process(flipper, now=1000.5)
    det.process(flipper, now=1001.0)
    assert det.flipper_count == 1
    assert len(changes) == 1


def test_attack_flood_throttles_aggregate_writes():
    # Every advertisement is reported per-hit (event/automations), but the
    # aggregate state is written only once when the attack window opens.
    changes, hits = [], []
    det = HomeOfFlippersDetector(
        OPTIONS,
        on_change=lambda: changes.append(True),
        on_attack=lambda hit, src: hits.append(hit),
    )
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    det.process(info, now=2000.5)
    det.process(info, now=2001.0)
    assert len(hits) == 3
    assert len(changes) == 1


def test_expire_refreshes_while_window_open_and_is_silent_when_idle():
    changes = []
    det = HomeOfFlippersDetector(OPTIONS, on_change=lambda: changes.append(True))
    # Idle tick: nothing to refresh.
    det.expire(now=100.0)
    assert changes == []
    # Attack opens the window, then a tick while it is still active refreshes.
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    before = len(changes)
    det.expire(now=2005.0)
    assert len(changes) > before


def test_attack_detection_can_be_disabled():
    opts = dict(OPTIONS, **{CONF_ENABLE_ATTACK_DETECTION: False})
    det = HomeOfFlippersDetector(opts)
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbcc")})
    det.process(info, now=2000.0)
    assert det.attack_active(now=2000.0) is False
