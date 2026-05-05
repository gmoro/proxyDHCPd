import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    # Use __new__ to avoid calling __init__ and exiting with sys.exit(2)
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1") is True
    assert config.ipAddressCheck("0.0.0.0") is True
    assert config.ipAddressCheck("255.255.255.255") is True

def test_ip_address_check_invalid_garbage():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1-garbage") is False
    assert config.ipAddressCheck("192.168.1.1   ") is False
    assert config.ipAddressCheck("garbage192.168.1.1") is False

def test_ip_address_check_invalid_range():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("256.256.256.256") is False
    assert config.ipAddressCheck("192.168.1.999") is False

def test_ip_address_check_invalid_format():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1") is False
    assert config.ipAddressCheck("192.168.1.1.1") is False
    assert config.ipAddressCheck("not-an-ip") is False
