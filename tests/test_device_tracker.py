"""Dynamic device_tracker tests."""
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.home_of_flippers.const import DOMAIN


@dataclass
class FakeInfo:
    address: str = "11:22:33:44:55:66"
    name: str | None = "Flipper Zilch"
    rssi: int | None = -40
    source: str | None = "proxy-1"
    service_uuids: list = field(
        default_factory=lambda: ["00003081-0000-1000-8000-00805f9b34fb"]
    )
    service_data: dict = field(default_factory=dict)
    manufacturer_data: dict = field(default_factory=dict)


async def test_device_tracker_created_on_detection(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Home of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    entry.runtime_data.process(FakeInfo(), now=1000.0)
    await hass.async_block_till_done()

    state = hass.states.get("device_tracker.flipper_112233445566")
    assert state is not None
    assert state.state == "home"
    assert state.attributes["variant"] == "Black"
    assert state.attributes["detection_type"] == "Name"
