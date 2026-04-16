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

def test_ipAddressCheck_cwe185():
    from proxydhcpd.proxyconfig import parse_config

    # Create an uninitialized instance to avoid sys.exit side-effects
    config = parse_config.__new__(parse_config)

    # Valid IP should pass
    assert config.ipAddressCheck("192.168.1.1") is True

    # Invalid IPs with trailing/leading garbage should fail (CWE-185)
    assert config.ipAddressCheck("192.168.1.1 ") is False
    assert config.ipAddressCheck(" 192.168.1.1") is False
    assert config.ipAddressCheck("192.168.1.1;cat /etc/passwd") is False
    assert config.ipAddressCheck("192.168.1.1garbage") is False
