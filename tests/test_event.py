"""Event entity tests."""
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.home_of_flippers.const import DOMAIN


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
    entry = MockConfigEntry(domain=DOMAIN, title="Home of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("event.home_of_flippers_ble_attack").state == "unknown"

    entry.runtime_data.process(FakeInfo(), now=2000.0)
    await hass.async_block_till_done()

    state = hass.states.get("event.home_of_flippers_ble_attack")
    assert state.attributes["event_type"] == "Windows Swift Pair Short"
    assert state.attributes["attack_type"] == "BLE_WINDOWS_SWIFT_PAIR_SHORT"
    assert state.attributes["address"] == "aa:bb:cc:dd:ee:ff"
