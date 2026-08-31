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


def test_ip_address_check_strict(mocker):
    # Mocking __init__ safely to avoid file reads
    mocker.patch('proxydhcpd.proxyconfig.parse_config.__init__', return_value=None)
    from proxydhcpd.proxyconfig import parse_config

    config = parse_config()

    # Valid IPs should pass
    assert config.ipAddressCheck("192.168.1.10") == True
    assert config.ipAddressCheck("10.0.0.1") == True
    assert config.ipAddressCheck("255.255.255.255") == True

    # Invalid IPs should fail (specifically testing for partial match trailing garbage)
    assert config.ipAddressCheck("192.168.1.10 garbage") == False
    assert config.ipAddressCheck("garbage 192.168.1.10") == False
    assert config.ipAddressCheck("192.168.1.10\n") == False
    assert config.ipAddressCheck("256.256.256.256") == False
