import pytest
from django.core.exceptions import ImproperlyConfigured

from config.scanning import scan_mode


def test_scanning_is_on_by_default_everywhere():
    assert scan_mode({}) == "clamav"
    assert scan_mode({}, True) == "clamav"


def test_render_free_defaults_to_disabled_and_enable_clamav_is_explicit():
    assert scan_mode({"RENDER": "true"}, True) == "disabled"
    assert scan_mode({"RENDER": "true", "ENABLE_CLAMAV": "true"}, True) == "clamav"
    assert scan_mode({"ENABLE_CLAMAV": "false"}, True) == "disabled"


@pytest.mark.parametrize("value", ["", "enabled", "2", "secret-canary"])
def test_invalid_enable_clamav_values_fail_without_leaking_values(value):
    with pytest.raises(ImproperlyConfigured) as error:
        scan_mode({"ENABLE_CLAMAV": value}, True)
    assert "secret-canary" not in str(error.value)


def test_development_bypass_is_rejected_in_production():
    assert scan_mode({"SCAN_MODE": "skip-development"}) == "skip-development"
    with pytest.raises(ImproperlyConfigured):
        scan_mode({"SCAN_MODE": "skip-development"}, True)


@pytest.mark.parametrize("value", ["", "none", "off", "clamav ", "DISABLED", "secret-canary"])
def test_unknown_scan_modes_fail_closed_without_values(value):
    with pytest.raises(ImproperlyConfigured) as error:
        scan_mode({"SCAN_MODE": value}, True)
    assert "secret-canary" not in str(error.value)


def test_disabling_scanning_in_production_requires_explicit_acknowledgement():
    with pytest.raises(ImproperlyConfigured) as error:
        scan_mode({"SCAN_MODE": "disabled"}, True)
    assert "ACCEPT_NO_MALWARE_SCANNING" in str(error.value)
    environment = {"SCAN_MODE": "disabled", "ACCEPT_NO_MALWARE_SCANNING": "1"}
    assert scan_mode(environment, True) == "disabled"


@pytest.mark.parametrize("value", ["0", "true", "yes", "", "11"])
def test_acknowledgement_must_be_exactly_one(value):
    with pytest.raises(ImproperlyConfigured):
        scan_mode({"SCAN_MODE": "disabled", "ACCEPT_NO_MALWARE_SCANNING": value}, True)
