import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict_match():
    # Use parse_config.__new__(parse_config) to create an uninitialized instance for testing
    config = parse_config.__new__(parse_config)

    # Valid IP address
    assert config.ipAddressCheck("192.168.1.1") == True

    # Invalid IP addresses with trailing garbage / command injection
    assert config.ipAddressCheck("192.168.1.1 garbage") == False
    assert config.ipAddressCheck("192.168.1.1; rm -rf /") == False
