import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie

def test_decode_packet_out_of_bounds_known():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing known option type without length
    payload = [0] * 236 + MagicCookie + [53]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

def test_ip_address_validation_strict_fullmatch():
    """
    Test that ipAddressCheck strictly validates the entire IP string.
    If re.match is used instead of re.fullmatch, inputs with trailing
    characters like newlines might incorrectly pass validation.
    """
    from proxydhcpd.proxyconfig import parse_config
    # Create an uninitialized instance for testing
    config_parser = parse_config.__new__(parse_config)

    # Valid IP
    assert config_parser.ipAddressCheck("192.168.1.1") is True

    # Invalid IPs with trailing characters that could bypass re.match
    assert config_parser.ipAddressCheck("192.168.1.1\nattack") is False
    assert config_parser.ipAddressCheck("192.168.1.1 garbage") is False
    assert config_parser.ipAddressCheck("192.168.1.1;") is False

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
