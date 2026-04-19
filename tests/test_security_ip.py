import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict():
    # Use __new__ to avoid side effects from __init__ (like reading proxy.ini and sys.exit)
    config = parse_config.__new__(parse_config)

    # Valid IPs should pass
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("0.0.0.0") == True
    assert config.ipAddressCheck("255.255.255.255") == True

    # Invalid IPs with trailing garbage should fail
    assert config.ipAddressCheck("192.168.1.1 garbage") == False
    assert config.ipAddressCheck("192.168.1.1;") == False
    assert config.ipAddressCheck("192.168.1.1\n") == False
    assert config.ipAddressCheck("192.168.1.1/24") == False

    # Other invalid IPs should fail
    assert config.ipAddressCheck("256.0.0.0") == False
    assert config.ipAddressCheck("invalid") == False
    assert config.ipAddressCheck("") == False
