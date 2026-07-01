"""Config and options flow for Home of Flippers."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from .const import (
    CONF_ATTACK_WINDOW,
    CONF_ENABLE_ATTACK_DETECTION,
    CONF_RATE_LIMIT_COUNT,
    CONF_RATE_LIMIT_WINDOW,
    CONF_RSSI_FLOOR,
    CONF_STALE_TIMEOUT,
    DEFAULT_ATTACK_WINDOW,
    DEFAULT_ENABLE_ATTACK_DETECTION,
    DEFAULT_RATE_LIMIT_COUNT,
    DEFAULT_RATE_LIMIT_WINDOW,
    DEFAULT_RSSI_FLOOR,
    DEFAULT_STALE_TIMEOUT,
    DOMAIN,
)


class HomeOfFlippersConfigFlow(ConfigFlow, domain=DOMAIN):
    """Single-instance config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        return self.async_create_entry(title="Home of Flippers", data={})

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return HomeOfFlippersOptionsFlow()


class HomeOfFlippersOptionsFlow(OptionsFlow):
    """Options for tuning detection thresholds."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_RSSI_FLOOR,
                    default=options.get(CONF_RSSI_FLOOR, DEFAULT_RSSI_FLOOR),
                ): vol.All(int, vol.Range(min=-127, max=0)),
                vol.Required(
                    CONF_STALE_TIMEOUT,
                    default=options.get(CONF_STALE_TIMEOUT, DEFAULT_STALE_TIMEOUT),
                ): vol.All(int, vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_ATTACK_WINDOW,
                    default=options.get(CONF_ATTACK_WINDOW, DEFAULT_ATTACK_WINDOW),
                ): vol.All(int, vol.Range(min=5, max=600)),
                vol.Required(
                    CONF_ENABLE_ATTACK_DETECTION,
                    default=options.get(
                        CONF_ENABLE_ATTACK_DETECTION, DEFAULT_ENABLE_ATTACK_DETECTION
                    ),
                ): bool,
                vol.Required(
                    CONF_RATE_LIMIT_COUNT,
                    default=options.get(CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT),
                ): vol.All(int, vol.Range(min=1, max=50)),
                vol.Required(
                    CONF_RATE_LIMIT_WINDOW,
                    default=options.get(
                        CONF_RATE_LIMIT_WINDOW, DEFAULT_RATE_LIMIT_WINDOW
                    ),
                ): vol.All(int, vol.Range(min=1, max=60)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
