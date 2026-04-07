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

def test_packet_str_zero_length_options():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing option type with length 0
    payload = [0] * 236 + MagicCookie + [53, 0]
    # This should not raise an IndexError when calling str()
    packet.DecodePacket(bytes(payload))
    packet.str()

def test_get_hardware_address_missing_hlen():
    packet = DhcpPacket()
    # Create a payload missing hlen
    packet.packet_data = [0] * 240
    # Delete the hlen field explicitly if it existed (though it should be 0 length)
    # The default packet_data initialization is [0]*240, hlen is at index 2, length 1
    # Let's ensure it doesn't fail when getting an empty option
    packet.GetHardwareAddress()
