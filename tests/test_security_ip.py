import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ipAddressCheck_fullmatch():
    # Create an uninitialized instance to avoid file system reads in __init__
    pc = parse_config.__new__(parse_config)

    # Valid IP should pass
    assert pc.ipAddressCheck("192.168.1.1") == True

    # Invalid IP with trailing garbage should fail
    assert pc.ipAddressCheck("192.168.1.1;") == False
    assert pc.ipAddressCheck("192.168.1.1; rm -rf /") == False

    # Invalid IP with leading garbage should fail
    assert pc.ipAddressCheck(" 192.168.1.1") == False

    # Out of bounds IP should fail
    assert pc.ipAddressCheck("256.256.256.256") == False
