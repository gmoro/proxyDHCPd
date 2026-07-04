import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ipAddressCheck_strict():
    # Use __new__ to avoid initialization side-effects like file system reads or sys.exit
    config = parse_config.__new__(parse_config)
    assert config.ipAddressCheck("192.168.1.1") == True
    # Verify that partial matches are rejected
    assert config.ipAddressCheck("192.168.1.1 trailing garbage") == False
    assert config.ipAddressCheck("192.168.1.1; rm -rf /") == False
