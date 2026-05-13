import os
import sys
import pytest

# Ensure the parent directory is resolvable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxydhcpd.proxyconfig import parse_config

def test_ip_address_check_strictness():
    # Use __new__ to avoid calling __init__ which tries to read files/exit
    config = parse_config.__new__(parse_config)

    # Valid IPs should return True
    assert config.ipAddressCheck("192.168.1.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True
    assert config.ipAddressCheck("0.0.0.0") == True

    # Invalid IPs
    # Partial match trailing garbage should fail
    assert config.ipAddressCheck("192.168.1.1.2") == False
    assert config.ipAddressCheck("192.168.1.1xyz") == False
    assert config.ipAddressCheck("abc192.168.1.1") == False
    assert config.ipAddressCheck("192.168.1.1/24") == False
