import pytest
from proxydhcpd.proxyconfig import parse_config

class TestProxyConfigRegex:
    def test_ip_address_check_valid(self, monkeypatch):
        monkeypatch.setattr(parse_config, "__init__", lambda self, config_file: None)
        config = parse_config("dummy.ini")
        assert config.ipAddressCheck("192.168.1.1") == True
        assert config.ipAddressCheck("255.255.255.255") == True
        assert config.ipAddressCheck("0.0.0.0") == True

    def test_ip_address_check_invalid(self, monkeypatch):
        monkeypatch.setattr(parse_config, "__init__", lambda self, config_file: None)
        config = parse_config("dummy.ini")
        assert config.ipAddressCheck("192.168.1.1 drop tables") == False
        assert config.ipAddressCheck("192.168.1.") == False
        assert config.ipAddressCheck("999.999.999.999") == False
        assert config.ipAddressCheck("not.an.ip.address") == False
