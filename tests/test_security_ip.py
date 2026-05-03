import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict():
    # Use __new__ to create an uninitialized instance to avoid sys.exit(2) during testing
    config = parse_config.__new__(parse_config)

    # Valid IPs
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("10.0.0.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True
    assert config.ipAddressCheck("0.0.0.0") == True

    # Invalid IPs (partial matches that would pass re.match but should fail re.fullmatch)
    assert config.ipAddressCheck("192.168.1.1/24") == False
    assert config.ipAddressCheck("192.168.1.1;rm -rf /") == False
    assert config.ipAddressCheck("192.168.1.1 ") == False
    assert config.ipAddressCheck(" 192.168.1.1") == False

    # Out of bounds IPs
    assert config.ipAddressCheck("256.1.1.1") == False
    assert config.ipAddressCheck("1.256.1.1") == False
    assert config.ipAddressCheck("1.1.256.1") == False
    assert config.ipAddressCheck("1.1.1.256") == False
