"""Tests for the pure detection engine."""
from dataclasses import dataclass, field

from custom_components.home_of_flippers.detection import (
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
    info = FakeInfo(
        name="Flipper Fake", service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"]
    )
    assert identify_flipper(info) is None


def test_matches_apple_popup_close_from_manufacturer_data():
    info = FakeInfo(
        manufacturer_data={0x004C: bytes.fromhex("0719010f2055aabbccddeeff0011223344")}
    )
    hits = match_attacks(info)
    assert (
        AttackHit(
            attack_type="BLE_APPLE_DEVICE_POPUP_CLOSE",
            matched_signature="4c000719010_2055_______________",
            address="aa:bb:cc:dd:ee:ff",
            rssi=-50,
        )
        in hits
    )


def test_matches_windows_swift_pair_from_manufacturer_data():
    info = FakeInfo(manufacturer_data={0x0006: bytes.fromhex("030080aabbccddeeff")})
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_WINDOWS_SWIFT_PAIR_SHORT" in types


def test_matches_android_fast_pair_from_service_data():
    info = FakeInfo(
        service_data={"0000fe2c-0000-1000-8000-00805f9b34fb": bytes.fromhex("aabbcc")}
    )
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_ANDROID_DEVICE_CONNECT" in types


def test_matches_hid_from_service_uuid():
    info = FakeInfo(service_uuids=["00001812-0000-1000-8000-00805f9b34fb"])
    types = {hit.attack_type for hit in match_attacks(info)}
    assert "BLE_HUMAN_INTERFACE_DEVICE" in types


def test_benign_advertisement_no_attack():
    info = FakeInfo(manufacturer_data={0x004C: bytes.fromhex("0215")})
    assert match_attacks(info) == []
