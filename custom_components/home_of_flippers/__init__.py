"""The Home of Flippers integration."""
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
from .detector import HomeOfFlippersDetector

type HomeOfFlippersConfigEntry = ConfigEntry[HomeOfFlippersDetector]

SCAN_INTERVAL = timedelta(seconds=15)


async def async_setup_entry(
    hass: HomeAssistant, entry: HomeOfFlippersConfigEntry
) -> bool:
    """Set up Home of Flippers from a config entry."""

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
        async_dispatcher_send(hass, SIGNAL_ATTACK.format(entry.entry_id), hit, source)
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

    detector = HomeOfFlippersDetector(
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
    hass: HomeAssistant, entry: HomeOfFlippersConfigEntry
) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(
    hass: HomeAssistant, entry: HomeOfFlippersConfigEntry
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
