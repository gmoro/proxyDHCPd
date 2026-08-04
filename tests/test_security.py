import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie

def test_decode_packet_out_of_bounds_known():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing known option type without length
    payload = [0] * 236 + MagicCookie + [53]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

def test_decode_packet_out_of_bounds_unknown():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing unknown option type without length
    payload = [0] * 236 + MagicCookie + [99]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

def test_decode_packet_out_of_bounds_length_exceeds():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing option type with length exceeding actual payload
    payload = [0] * 236 + MagicCookie + [53, 5]
    # This should not raise an IndexError or handle it safely
    packet.DecodePacket(bytes(payload))

def test_decode_packet_out_of_bounds_unknown_length_exceeds():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing unknown option type with length exceeding actual payload
    payload = [0] * 236 + MagicCookie + [99, 10]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

def test_ip_address_check_strict_matching():
    import unittest.mock as mock
    from proxydhcpd.proxyconfig import parse_config

    # We can mock parse_config's __init__ to avoid setup logic
    with mock.patch.object(parse_config, '__init__', lambda self, configfile='proxy.ini': None):
        config_parser = parse_config()

        # Valid IPs should pass
        assert config_parser.ipAddressCheck("192.168.1.1") == True
        assert config_parser.ipAddressCheck("255.255.255.255") == True
        assert config_parser.ipAddressCheck("0.0.0.0") == True

        # Invalid IPs should fail (including those with trailing garbage)
        assert config_parser.ipAddressCheck("192.168.1.1 trailing") == False
        assert config_parser.ipAddressCheck("192.168.1.1; rm -rf /") == False
        assert config_parser.ipAddressCheck("192.168.1.1\n") == False
