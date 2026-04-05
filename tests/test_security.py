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

def test_decode_packet_truncated_dos():
    packet = DhcpPacket()
    # Create an extremely truncated packet
    payload = [0] * 2
    packet.DecodePacket(bytes(payload))

    # These should safely handle missing/empty arrays without raising IndexError
    hw = packet.GetHardwareAddress()
    assert hw == []

    packet_str = packet.str()
    assert "op :" in packet_str

def test_decode_packet_empty_options_dos():
    packet = DhcpPacket()
    packet.DecodePacket(bytes([0]*240))
    # Inject empty arrays to simulate malformed/missing options
    packet.options_data['dhcp_message_type'] = []
    packet.options_data['client_identifier'] = []
    packet.options_data['vendor_class_identifier'] = []

    # This should not raise IndexError when printing
    packet_str = packet.str()
    assert "dhcp_message_type :" in packet_str
