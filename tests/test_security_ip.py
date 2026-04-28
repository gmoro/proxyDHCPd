import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    # Use __new__ to avoid calling __init__ and exiting with sys.exit(2)
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("192.168.1.1") is True
    assert pc.ipAddressCheck("255.255.255.255") is True
    assert pc.ipAddressCheck("0.0.0.0") is True

def test_ip_address_check_invalid_trailing_garbage():
    pc = parse_config.__new__(parse_config)
    # Ensure strict validation with re.fullmatch rejects trailing garbage
    assert pc.ipAddressCheck("192.168.1.1 trailing_garbage") is False
    assert pc.ipAddressCheck("192.168.1.1/24") is False
    assert pc.ipAddressCheck("192.168.1.1 ") is False

def test_ip_address_check_invalid_leading_garbage():
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("garbage 192.168.1.1") is False
    assert pc.ipAddressCheck(" 192.168.1.1") is False

def test_ip_address_check_invalid_format():
    pc = parse_config.__new__(parse_config)
    assert pc.ipAddressCheck("256.1.1.1") is False
    assert pc.ipAddressCheck("192.168.1") is False
    assert pc.ipAddressCheck("not.an.ip.address") is False
