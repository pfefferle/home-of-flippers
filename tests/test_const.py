"""Sanity checks for constants."""
from custom_components.home_of_flippers import const


def test_attack_types_are_unique_and_nonempty():
    assert len(const.ATTACK_TYPES) == len(set(const.ATTACK_TYPES))
    assert all(const.ATTACK_TYPES)


def test_flipper_variants_use_base_suffix():
    assert all(uuid.endswith(const.BASE_UUID_SUFFIX) for uuid in const.FLIPPER_VARIANTS)
