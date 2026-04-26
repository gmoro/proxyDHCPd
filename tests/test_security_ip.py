import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ipAddressCheck_strict():
    # Mocking __init__ to avoid config parsing during test instantiation
    parser = parse_config.__new__(parse_config)

    # Valid IPs
    assert parser.ipAddressCheck("192.168.1.1") == True
    assert parser.ipAddressCheck("255.255.255.255") == True
    assert parser.ipAddressCheck("0.0.0.0") == True

    # Invalid IPs
    assert parser.ipAddressCheck("192.168.1.256") == False
    assert parser.ipAddressCheck("192.168.1") == False
    assert parser.ipAddressCheck("not.an.ip.address") == False

    # Vulnerability check (CWE-185 partial match)
    assert parser.ipAddressCheck("192.168.1.1; rm -rf /") == False
    assert parser.ipAddressCheck("192.168.1.1\nmalicious") == False
