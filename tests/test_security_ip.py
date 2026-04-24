import pytest
import sys
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_valid():
    # Use __new__ to instantiate parse_config without calling __init__
    # to avoid the file system/sys.exit side-effects during initialization
    parser = parse_config.__new__(parse_config)

    assert parser.ipAddressCheck("192.168.1.1") is True
    assert parser.ipAddressCheck("0.0.0.0") is True
    assert parser.ipAddressCheck("255.255.255.255") is True

def test_ip_address_check_invalid_trailing_garbage():
    parser = parse_config.__new__(parse_config)

    assert parser.ipAddressCheck("192.168.1.1 malformed") is False
    assert parser.ipAddressCheck("192.168.1.1\n") is False
    assert parser.ipAddressCheck("192.168.1.1; rm -rf /") is False
    assert parser.ipAddressCheck("192.168.1.1.5") is False
    assert parser.ipAddressCheck("malformed 192.168.1.1") is False

def test_ip_address_check_invalid_format():
    parser = parse_config.__new__(parse_config)

    assert parser.ipAddressCheck("192.168.1") is False
    assert parser.ipAddressCheck("192.168.1.256") is False
    assert parser.ipAddressCheck("invalid") is False
    assert parser.ipAddressCheck("") is False
