"""Constants for the Home of Flippers integration."""

DOMAIN = "home_of_flippers"

PLATFORMS = ["binary_sensor", "sensor", "device_tracker", "event"]

# --- Flipper Zero identification ---------------------------------------------
BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"
FLIPPER_UUID_PREFIX = "0000308"
FLIPPER_VARIANTS = {
    "00003081" + BASE_UUID_SUFFIX: "Black",
    "00003082" + BASE_UUID_SUFFIX: "White",
    "00003083" + BASE_UUID_SUFFIX: "Transparent",
}
# Flipper Devices Inc BLE OUIs (lowercase, colon-separated)
FLIPPER_OUIS = ("80:e1:26", "80:e1:27", "0c:fa:22")

# --- BLE attack signatures ("_" = one wildcard nibble) -----------------------
ATTACK_SIGNATURES = (
    ("00001812-0000-1000-8000-00805f9b34fb", "BLE_HUMAN_INTERFACE_DEVICE"),
    ("4c000719010_2055_______________", "BLE_APPLE_DEVICE_POPUP_CLOSE"),
    ("4c000f05c00____________________", "BLE_APPLE_ACTION_MODAL_LONG"),
    ("4c00071907_____________________", "BLE_APPLE_DEVICE_CONNECT"),
    ("4c0004042a0000000f05c1__604c950", "BLE_APPLE_DEVICE_SETUP"),
    ("2cfe___________________________", "BLE_ANDROID_DEVICE_CONNECT"),
    ("750042098102141503210109____01_", "BLE_SAMSUNG_BUDS_POPUP_LONG"),
    ("7500010002000101ff000043_______", "BLE_SAMSUNG_WATCH_PAIR_LONG"),
    ("0600030080_____________________", "BLE_WINDOWS_SWIFT_PAIR_SHORT"),
    ("ff006db643ce97fe427c___________", "BLE_LOVE_TOYS_SHORT_DISTANCE"),
)
ATTACK_TYPES = tuple(dict.fromkeys(attack_type for _, attack_type in ATTACK_SIGNATURES))

# --- Home Assistant bus events -----------------------------------------------
EVENT_FLIPPER_DETECTED = "home_of_flippers_flipper_detected"
EVENT_ATTACK_DETECTED = "home_of_flippers_attack_detected"

# --- Dispatcher signals (formatted with the entry_id at runtime) -------------
SIGNAL_UPDATE = "home_of_flippers_update_{}"
SIGNAL_NEW_FLIPPER = "home_of_flippers_new_flipper_{}"
SIGNAL_ATTACK = "home_of_flippers_attack_{}"

# --- Options -----------------------------------------------------------------
CONF_RSSI_FLOOR = "rssi_floor"
CONF_STALE_TIMEOUT = "stale_timeout"
CONF_ATTACK_WINDOW = "attack_window"
CONF_ENABLE_ATTACK_DETECTION = "enable_attack_detection"
CONF_RATE_LIMIT_COUNT = "rate_limit_count"
CONF_RATE_LIMIT_WINDOW = "rate_limit_window"

DEFAULT_RSSI_FLOOR = -90
DEFAULT_STALE_TIMEOUT = 300
DEFAULT_ATTACK_WINDOW = 60
DEFAULT_ENABLE_ATTACK_DETECTION = True
DEFAULT_RATE_LIMIT_COUNT = 3
DEFAULT_RATE_LIMIT_WINDOW = 5
