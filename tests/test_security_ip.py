import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict():
    # Use __new__ to avoid calling __init__ which expects a config file and might sys.exit()
    config = parse_config.__new__(parse_config)

    # Valid IPs
    assert config.ipAddressCheck("192.168.1.1") is True
    assert config.ipAddressCheck("10.0.0.1") is True
    assert config.ipAddressCheck("255.255.255.255") is True

    # Invalid IPs with trailing garbage (should be rejected)
    assert config.ipAddressCheck("192.168.1.1\n rm -rf /") is False
    assert config.ipAddressCheck("192.168.1.1 trailing garbage") is False
    assert config.ipAddressCheck("192.168.1.1!") is False
    assert config.ipAddressCheck("  192.168.1.1  ") is False
