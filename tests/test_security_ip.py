import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("10.0.0.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True
    assert config.ipAddressCheck("0.0.0.0") == True

def test_ip_address_check_invalid_partial_match():
    # Test for CWE-185 vulnerability: partial matches with trailing garbage
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1 garbage") == False
    assert config.ipAddressCheck("10.0.0.1; rm -rf /") == False
    assert config.ipAddressCheck("192.168.1.1\n") == False

def test_ip_address_check_invalid():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("256.256.256.256") == False
    assert config.ipAddressCheck("invalid_ip") == False
    assert config.ipAddressCheck("192.168.1") == False
