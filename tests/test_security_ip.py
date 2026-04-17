import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict_validation():
    # Use __new__ to instantiate without running __init__ side-effects
    pc = parse_config.__new__(parse_config)

    # Valid IPs
    assert pc.ipAddressCheck("192.168.1.1") is True
    assert pc.ipAddressCheck("10.0.0.1") is True

    # Invalid IPs with trailing garbage that might bypass re.match
    assert pc.ipAddressCheck("192.168.1.1 garbage") is False
    assert pc.ipAddressCheck("192.168.1.1.5") is False
    assert pc.ipAddressCheck("192.168.1.1/24") is False
