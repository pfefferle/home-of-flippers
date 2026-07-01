"""BLE attack event entity."""
from __future__ import annotations

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import ATTACK_TYPES, DOMAIN, SIGNAL_ATTACK
from .detection import AttackHit, humanize_attack_type


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([BleAttackEvent(entry)])


class BleAttackEvent(EventEntity):
    """Fires whenever a BLE attack signature is matched."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_name = "BLE Attack"
    _attr_icon = "mdi:shield-alert"
    _attr_device_class = EventDeviceClass.MOTION
    _attr_event_types = [humanize_attack_type(t) for t in ATTACK_TYPES]

    def __init__(self, entry) -> None:
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_ble_attack"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Home of Flippers",
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
            humanize_attack_type(hit.attack_type),
            {
                "attack_type": hit.attack_type,
                "matched_signature": hit.matched_signature,
                "address": hit.address,
                "rssi": hit.rssi,
                "source": source,
            },
        )
        self.async_write_ha_state()
