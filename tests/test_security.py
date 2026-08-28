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


def test_ip_address_check_strict_matching(mocker):
    from proxydhcpd.proxyconfig import parse_config

    # Mock the parse_config __init__ to avoid reading config files
    mocker.patch('proxydhcpd.proxyconfig.parse_config.__init__', return_value=None)

    config = parse_config()

    # Valid IPs should pass
    assert config.ipAddressCheck("192.168.1.1") is True
    assert config.ipAddressCheck("10.0.0.255") is True

    # Partially matching IPs should fail with fullmatch
    assert config.ipAddressCheck("192.168.1.1.evil") is False
    assert config.ipAddressCheck("192.168.1.1 ") is False
    assert config.ipAddressCheck(" 192.168.1.1") is False
    assert config.ipAddressCheck("192.168.1.1\n") is False
    assert config.ipAddressCheck("evil192.168.1.1") is False
