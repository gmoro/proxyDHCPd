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

from proxydhcpd.proxyconfig import parse_config
import os
import unittest.mock as mock

@mock.patch('os.access', return_value=True)
@mock.patch('configparser.ConfigParser.read')
@mock.patch('configparser.ConfigParser.sections', return_value=[])
@mock.patch('proxydhcpd.proxyconfig.parse_config.__init__', return_value=None)
def test_ipAddressCheck_strict_validation(mock_init, mock_sections, mock_read, mock_access):
    config = parse_config()
    # Test valid IP
    assert config.ipAddressCheck("192.168.1.1") is True
    # Test invalid IP with trailing garbage
    assert config.ipAddressCheck("192.168.1.1; rm -rf /") is False
    # Test invalid IP with trailing space
    assert config.ipAddressCheck("192.168.1.1 ") is False
    # Test invalid IP with leading garbage
    assert config.ipAddressCheck("echo hello; 192.168.1.1") is False
