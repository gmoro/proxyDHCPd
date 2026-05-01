import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict():
    # Use __new__ to instantiate parse_config without executing __init__ which attempts to read files/exit
    pc = parse_config.__new__(parse_config)

    # Valid IPs
    assert pc.ipAddressCheck("192.168.1.1") is True
    assert pc.ipAddressCheck("10.0.0.1") is True
    assert pc.ipAddressCheck("255.255.255.255") is True
    assert pc.ipAddressCheck("0.0.0.0") is True

    # Invalid IPs (garbage trailing)
    assert pc.ipAddressCheck("192.168.1.1; echo exploit") is False
    assert pc.ipAddressCheck("10.0.0.1/24") is False
    assert pc.ipAddressCheck("192.168.1.1 ") is False
    assert pc.ipAddressCheck("192.168.1.1\n") is False

    # Invalid IPs (garbage leading)
    assert pc.ipAddressCheck(" 192.168.1.1") is False
    assert pc.ipAddressCheck("exploit; 192.168.1.1") is False

    # Invalid IPs (malformed)
    assert pc.ipAddressCheck("256.256.256.256") is False
    assert pc.ipAddressCheck("192.168.1") is False
    assert pc.ipAddressCheck("192.168.1.1.1") is False
    assert pc.ipAddressCheck("not.an.ip.address") is False
