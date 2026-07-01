"""Aggregate entity tests."""
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.home_of_flippers.const import DOMAIN


async def test_aggregate_entities_created(hass: HomeAssistant):
    entry = MockConfigEntry(domain=DOMAIN, title="Home of Flippers")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("binary_sensor.home_of_flippers_flipper_zero_detected")
    assert hass.states.get("binary_sensor.home_of_flippers_ble_attack_detected")
    assert hass.states.get("sensor.home_of_flippers_flippers_nearby").state == "0"
    assert hass.states.get("sensor.home_of_flippers_ble_attacks_per_minute")
    assert hass.states.get("sensor.home_of_flippers_last_attack_type")
