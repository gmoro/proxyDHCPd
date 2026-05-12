import pytest
import re
from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strict():
    cp = parse_config.__new__(parse_config)

    # Valid IP
    assert cp.ipAddressCheck("192.168.1.1") == True

    # Invalid IP with trailing garbage
    assert cp.ipAddressCheck("192.168.1.1\nfoobar") == False
    assert cp.ipAddressCheck("192.168.1.1 ") == False
    assert cp.ipAddressCheck(" 192.168.1.1") == False
    assert cp.ipAddressCheck("192.168.1.1.5") == False
