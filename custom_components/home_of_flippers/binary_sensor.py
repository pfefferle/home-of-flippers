"""Aggregate binary sensors for Home of Flippers."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant
import homeassistant.util.dt as dt_util
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import HomeOfFlippersBaseEntity


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities(
        [FlipperDetectedBinarySensor(entry), AttackDetectedBinarySensor(entry)]
    )


class FlipperDetectedBinarySensor(HomeOfFlippersBaseEntity, BinarySensorEntity):
    _attr_name = "Flipper Zero Detected"
    _attr_icon = "mdi:dolphin"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_flipper_detected"

    @property
    def is_on(self) -> bool:
        return self._detector.has_live_flipper


class AttackDetectedBinarySensor(HomeOfFlippersBaseEntity, BinarySensorEntity):
    _attr_name = "BLE Attack Detected"
    _attr_icon = "mdi:shield-alert"
    _attr_device_class = BinarySensorDeviceClass.SAFETY

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_attack_detected"

    @property
    def is_on(self) -> bool:
        return self._detector.attack_active(dt_util.utcnow().timestamp())
