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

def test_dhcppacket_str_unhandled_exceptions():
    packet = DhcpPacket()
    # Test short packet formatting doesn't raise Unhandled Exception
    packet.packet_data = [0] * 10
    # Should not raise exception
    res = packet.str()
    assert "# Header fields" in res

def test_dhcppacket_gethardwareaddress_out_of_bounds():
    packet = DhcpPacket()
    packet.DecodePacket(b"\x00" * 30 + b"\xff")
    # This should not raise an IndexError when hlen is empty
    mac = packet.GetHardwareAddress()
    # When packet is truncated, it returns the available bytes instead of throwing an error
    assert type(mac) == list
