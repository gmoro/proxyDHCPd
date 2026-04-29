import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    # Use __new__ to avoid file system reading side-effects of __init__
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("10.0.0.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True
    assert config.ipAddressCheck("0.0.0.0") == True

def test_ip_address_check_invalid():
    config = parse_config.__new__(parse_config)
    # Invalid characters trailing a valid IP
    assert config.ipAddressCheck("192.168.1.1 trailing garbage") == False
    assert config.ipAddressCheck("192.168.1.1 ") == False
    assert config.ipAddressCheck(" 192.168.1.1") == False
    # Other invalid IPs
    assert config.ipAddressCheck("256.256.256.256") == False
    assert config.ipAddressCheck("192.168.1") == False
    assert config.ipAddressCheck("not.an.ip") == False
    assert config.ipAddressCheck("") == False
