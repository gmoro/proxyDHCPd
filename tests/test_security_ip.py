import pytest
from proxydhcpd.proxyconfig import parse_config

class TestSecurityIP:
    def setup_method(self):
        # Create uninitialized instance to avoid sys.exit side-effects
        self.config = parse_config.__new__(parse_config)

    def test_ip_address_check_valid(self):
        assert self.config.ipAddressCheck("192.168.1.1") == True
        assert self.config.ipAddressCheck("10.0.0.1") == True
        assert self.config.ipAddressCheck("255.255.255.255") == True
        assert self.config.ipAddressCheck("0.0.0.0") == True

    def test_ip_address_check_invalid_trailing_garbage(self):
        # Prevent CWE-185 partial matching
        assert self.config.ipAddressCheck("192.168.1.1.bad") == False
        assert self.config.ipAddressCheck("192.168.1.1; rm -rf /") == False
        assert self.config.ipAddressCheck("192.168.1.1\n10.0.0.1") == False

    def test_ip_address_check_invalid_format(self):
        assert self.config.ipAddressCheck("192.168.1") == False
        assert self.config.ipAddressCheck("192.168.1.1.1") == False
        assert self.config.ipAddressCheck("not an ip") == False
        assert self.config.ipAddressCheck("256.256.256.256") == False
