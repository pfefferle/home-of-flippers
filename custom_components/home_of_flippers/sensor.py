"""Aggregate sensors for Home of Flippers."""
from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
import homeassistant.util.dt as dt_util
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import HomeOfFlippersBaseEntity


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities(
        [
            FlippersNearbySensor(entry),
            AttacksPerMinuteSensor(entry),
            LastAttackTypeSensor(entry),
        ]
    )


class FlippersNearbySensor(HomeOfFlippersBaseEntity, SensorEntity):
    _attr_name = "Flippers Nearby"
    _attr_icon = "mdi:dolphin"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "flippers"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_flippers_nearby"

    @property
    def native_value(self) -> int:
        return self._detector.flipper_count


class AttacksPerMinuteSensor(HomeOfFlippersBaseEntity, SensorEntity):
    _attr_name = "BLE Attacks per Minute"
    _attr_icon = "mdi:bluetooth-alert"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "attacks/min"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_attacks_per_minute"

    @property
    def native_value(self) -> int:
        return self._detector.attack_count_last_minute(dt_util.utcnow().timestamp())


class LastAttackTypeSensor(HomeOfFlippersBaseEntity, SensorEntity):
    _attr_name = "Last Attack Type"
    _attr_icon = "mdi:bluetooth-alert"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.entry_id}_last_attack_type"

    @property
    def native_value(self) -> str:
        return self._detector.last_attack_type or "none"
