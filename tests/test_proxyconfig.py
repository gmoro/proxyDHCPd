import pytest
from unittest.mock import patch
from proxydhcpd.proxyconfig import parse_config

@pytest.fixture
def config():
    with patch.object(parse_config, '__init__', lambda self: None):
        return parse_config()

def test_ip_address_check_valid(config):
    assert config.ipAddressCheck("192.168.1.1") is True
    assert config.ipAddressCheck("10.0.0.0") is True
    assert config.ipAddressCheck("255.255.255.255") is True

def test_ip_address_check_invalid(config):
    assert config.ipAddressCheck("192.168.1.256") is False
    assert config.ipAddressCheck("not.an.ip") is False

def test_ip_address_check_malicious(config):
    # Tests preventing CWE-185
    assert config.ipAddressCheck("192.168.1.1 ") is False
    assert config.ipAddressCheck("192.168.1.1; rm -rf /") is False
    assert config.ipAddressCheck(" 192.168.1.1") is False
    assert config.ipAddressCheck("192.168.1.1\n") is False
