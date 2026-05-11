import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("192.168.1.1") == True
    assert pc.ipAddressCheck("10.0.0.1") == True
    assert pc.ipAddressCheck("255.255.255.255") == True
    assert pc.ipAddressCheck("0.0.0.0") == True

def test_ip_address_check_invalid():
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("256.1.1.1") == False
    assert pc.ipAddressCheck("192.168.1.1.1") == False
    assert pc.ipAddressCheck("192.168.1") == False
    assert pc.ipAddressCheck("not.an.ip.address") == False

def test_ip_address_check_injection():
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("192.168.1.1; rm -rf /") == False
    assert pc.ipAddressCheck("10.0.0.1\nwhoami") == False
    assert pc.ipAddressCheck(" 192.168.1.1") == False
    assert pc.ipAddressCheck("192.168.1.1 ") == False
