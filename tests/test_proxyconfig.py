import pytest
from unittest.mock import patch
from proxydhcpd.proxyconfig import parse_config

class TestParseConfig:
    @patch.object(parse_config, '__init__', return_value=None)
    def test_ipAddressCheck_valid(self, mock_init):
        config = parse_config()
        assert config.ipAddressCheck("192.168.1.1") == True
        assert config.ipAddressCheck("10.0.0.1") == True
        assert config.ipAddressCheck("255.255.255.255") == True
        assert config.ipAddressCheck("0.0.0.0") == True

    @patch.object(parse_config, '__init__', return_value=None)
    def test_ipAddressCheck_invalid(self, mock_init):
        config = parse_config()
        # Invalid format
        assert config.ipAddressCheck("192.168.1") == False
        assert config.ipAddressCheck("256.0.0.1") == False
        # Injection / trailing garbage
        assert config.ipAddressCheck("192.168.1.1; rm -rf /") == False
        assert config.ipAddressCheck("192.168.1.1 ") == False
        assert config.ipAddressCheck(" 192.168.1.1") == False
        assert config.ipAddressCheck("192.168.1.1\n") == False
        assert config.ipAddressCheck("192.168.1.1a") == False
