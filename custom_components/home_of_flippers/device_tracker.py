"""Dynamic per-Flipper device trackers."""
from __future__ import annotations

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.core import HomeAssistant, callback
import homeassistant.util.dt as dt_util
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

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
        async_add_entities([HomeOfFlippersTracker(entry, flipper.address)])

    entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_NEW_FLIPPER.format(entry.entry_id), _add)
    )


class HomeOfFlippersTracker(ScannerEntity):
    """Tracks a single Flipper by MAC address (home when recently seen)."""

    _attr_should_poll = False
    _attr_icon = "mdi:dolphin"

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
    def is_connected(self) -> bool:
        return self._record() is not None

    @property
    def extra_state_attributes(self) -> dict:
        record = self._record()
        if record is None:
            return {"address": self._address}
        info: FlipperInfo = record["info"]
        return {
            "address": self._address,
            "variant": info.variant,
            "rssi": info.rssi,
            "detection_type": info.detection_type,
            "flipper_name": info.name,
            "uid": info.uid,
            "source": record.get("source"),
            "first_seen": dt_util.utc_from_timestamp(record["first_seen"]).isoformat(),
            "last_seen": dt_util.utc_from_timestamp(record["last_seen"]).isoformat(),
        }

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_UPDATE.format(self._entry.entry_id),
                self.async_write_ha_state,
            )
        )
