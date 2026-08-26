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

from unittest.mock import patch
from proxydhcpd.proxyconfig import parse_config

@patch("proxydhcpd.proxyconfig.parse_config.__init__", return_value=None)
def test_ipAddressCheck_cwe_185(mock_init):
    # Instantiate the class without calling its actual __init__ to avoid config parsing
    config = parse_config()

    # Test valid IP
    assert config.ipAddressCheck("192.168.1.1") is True

    # Test invalid partial match (CWE-185 vulnerability)
    assert config.ipAddressCheck("192.168.1.1.evil.com") is False
    assert config.ipAddressCheck("192.168.1.1foo") is False
    assert config.ipAddressCheck("bad192.168.1.1") is False
