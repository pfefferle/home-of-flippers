"""Pure BLE detection logic for Home of Flippers.

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
    """Wildcard match ('_' = one nibble).

    Mirrors upstream semantics: overlapping positions must match (wildcards
    excepted), and the candidate must be at least as long as the signature's
    fixed (non-wildcard) portion.
    """
    candidate = candidate.lower()
    signature = signature.lower()
    fixed_length = len(signature.replace("_", ""))
    if len(candidate) < fixed_length:
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
