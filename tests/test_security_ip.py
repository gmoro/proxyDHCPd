import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ipAddressCheck_valid():
    # Use __new__ to avoid triggering the constructor's side-effects (e.g., file reading, sys.exit)
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("0.0.0.0") == True
    assert config.ipAddressCheck("255.255.255.255") == True
    assert config.ipAddressCheck("10.0.0.1") == True

def test_ipAddressCheck_invalid_injection():
    config = parse_config.__new__(parse_config)
    # The previous re.match vulnerability would return True for this due to partial matching
    assert config.ipAddressCheck("192.168.1.1; rm -rf /") == False
    assert config.ipAddressCheck("192.168.1.1 ") == False

def test_ipAddressCheck_invalid_format():
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1") == False
    assert config.ipAddressCheck("256.256.256.256") == False
    assert config.ipAddressCheck("invalid_ip") == False
    assert config.ipAddressCheck("") == False
