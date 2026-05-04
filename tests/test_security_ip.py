import unittest
from proxydhcpd.proxyconfig import parse_config

class TestSecurityIP(unittest.TestCase):
    def setUp(self):
        # Create uninitialized instance to avoid file system side effects
        self.config = parse_config.__new__(parse_config)

    def test_valid_ip(self):
        self.assertTrue(self.config.ipAddressCheck("192.168.1.1"))
        self.assertTrue(self.config.ipAddressCheck("0.0.0.0"))
        self.assertTrue(self.config.ipAddressCheck("255.255.255.255"))

    def test_invalid_ip_trailing_garbage(self):
        # This tests for CWE-185 where partial match would pass
        self.assertFalse(self.config.ipAddressCheck("192.168.1.1; DROP TABLE users"))
        self.assertFalse(self.config.ipAddressCheck("192.168.1.1/24"))
        self.assertFalse(self.config.ipAddressCheck("192.168.1.1 "))

    def test_invalid_ip_format(self):
        self.assertFalse(self.config.ipAddressCheck("256.256.256.256"))
        self.assertFalse(self.config.ipAddressCheck("192.168.1"))
        self.assertFalse(self.config.ipAddressCheck("not an ip"))

if __name__ == '__main__':
    unittest.main()
