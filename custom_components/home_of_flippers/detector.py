"""Runtime state for Home of Flippers detections."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any

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
)
from .detection import AttackHit, FlipperInfo, identify_flipper, match_attacks


class HomeOfFlippersDetector:
    """Holds live flipper/attack state and pushes updates via callbacks."""

    def __init__(
        self,
        options: dict[str, Any],
        *,
        on_change: Callable[[], None] | None = None,
        on_new_flipper: Callable[[FlipperInfo, str | None], None] | None = None,
        on_attack: Callable[[AttackHit, str | None], None] | None = None,
    ) -> None:
        self._options = options
        self._on_change = on_change
        self._on_new_flipper = on_new_flipper
        self._on_attack = on_attack

        self.live_flippers: dict[str, dict[str, Any]] = {}
        self._attacks: deque[tuple[float, AttackHit]] = deque()
        self._new_flipper_times: deque[float] = deque()
        self._rate_limited_until = 0.0
        self._last_attack_type: str | None = None

    # --- options helpers -----------------------------------------------------
    def _opt(self, key: str, default: Any) -> Any:
        value = self._options.get(key, default)
        return default if value is None else value

    # --- main entry ----------------------------------------------------------
    def process(self, info, now: float) -> None:
        """Process a single advertisement."""
        rssi = info.rssi if info.rssi is not None else 0
        if rssi < self._opt(CONF_RSSI_FLOOR, DEFAULT_RSSI_FLOOR):
            return

        flipper = identify_flipper(info)
        if flipper is not None:
            self._handle_flipper(flipper, getattr(info, "source", None), now)

        if self._opt(CONF_ENABLE_ATTACK_DETECTION, DEFAULT_ENABLE_ATTACK_DETECTION):
            for hit in match_attacks(info):
                self._handle_attack(hit, getattr(info, "source", None), now)

    def _handle_flipper(
        self, flipper: FlipperInfo, source: str | None, now: float
    ) -> None:
        is_new = flipper.address not in self.live_flippers
        if is_new:
            window = self._opt(CONF_RATE_LIMIT_WINDOW, DEFAULT_RATE_LIMIT_WINDOW)
            count = self._opt(CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT)
            self._new_flipper_times.append(now)
            while self._new_flipper_times and now - self._new_flipper_times[0] > window:
                self._new_flipper_times.popleft()
            if len(self._new_flipper_times) >= count:
                self._rate_limited_until = now + window
            if now < self._rate_limited_until:
                # Suspected spoof-flood: do not trust this device.
                return
            self.live_flippers[flipper.address] = {
                "info": flipper,
                "first_seen": now,
                "last_seen": now,
                "source": source,
            }
            if self._on_new_flipper is not None:
                self._on_new_flipper(flipper, source)
        else:
            record = self.live_flippers[flipper.address]
            record["info"] = flipper
            record["last_seen"] = now
            record["source"] = source
        self._changed()

    def _handle_attack(self, hit: AttackHit, source: str | None, now: float) -> None:
        self._attacks.append((now, hit))
        self._last_attack_type = hit.attack_type
        if self._on_attack is not None:
            self._on_attack(hit, source)
        self._changed()

    # --- expiry --------------------------------------------------------------
    def expire(self, now: float) -> None:
        """Remove stale flippers and drop attacks older than one minute."""
        stale = self._opt(CONF_STALE_TIMEOUT, DEFAULT_STALE_TIMEOUT)
        removed = [
            mac
            for mac, rec in self.live_flippers.items()
            if now - rec["last_seen"] > stale
        ]
        for mac in removed:
            del self.live_flippers[mac]
        while self._attacks and now - self._attacks[0][0] > 60:
            self._attacks.popleft()
        if removed:
            self._changed()

    def _changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    # --- read-only state -----------------------------------------------------
    @property
    def rate_limited(self) -> bool:
        return len(self._new_flipper_times) >= self._opt(
            CONF_RATE_LIMIT_COUNT, DEFAULT_RATE_LIMIT_COUNT
        )

    @property
    def flipper_count(self) -> int:
        return len(self.live_flippers)

    @property
    def has_live_flipper(self) -> bool:
        return bool(self.live_flippers)

    @property
    def last_attack_type(self) -> str | None:
        return self._last_attack_type

    def attack_count_last_minute(self, now: float) -> int:
        return sum(1 for ts, _ in self._attacks if now - ts <= 60)

    def attack_active(self, now: float) -> bool:
        window = self._opt(CONF_ATTACK_WINDOW, DEFAULT_ATTACK_WINDOW)
        return any(now - ts <= window for ts, _ in self._attacks)
