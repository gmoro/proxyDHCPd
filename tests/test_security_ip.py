import pytest
from proxydhcpd.proxyconfig import parse_config

def test_ipAddressCheck_strict_validation():
    config = parse_config.__new__(parse_config)

    assert config.ipAddressCheck("192.168.1.1") is True
    assert config.ipAddressCheck("192.168.1.1 trailing garbage") is False
    assert config.ipAddressCheck("192.168.1.1\n") is False
    assert config.ipAddressCheck("256.256.256.256") is False
