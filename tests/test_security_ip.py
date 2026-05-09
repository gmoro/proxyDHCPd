import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_validation():
    # To test parse_config without executing __init__ logic
    config = parse_config.__new__(parse_config)

    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True

    # These should be False due to strict validation
    assert config.ipAddressCheck("192.168.1.1; echo pwn") == False
    assert config.ipAddressCheck("192.168.1.1 ") == False
    assert config.ipAddressCheck(" 192.168.1.1") == False
    assert config.ipAddressCheck("192.168.1.1\n") == False
