"""Shared base entity for Home of Flippers."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity

from .const import DOMAIN, SIGNAL_UPDATE


class HomeOfFlippersBaseEntity(Entity):
    """Base class wiring device info and dispatcher updates."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry) -> None:
        self._entry = entry
        self._detector = entry.runtime_data
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Home of Flippers",
            manufacturer="Home of Flippers",
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
