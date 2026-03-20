import pytest
import socket
from struct import pack
from proxydhcpd.dhcplib.dhcp_basic_packet import DhcpBasicPacket

def test_malformed_packet_missing_length():
    packet = [0] * 236
    # magic cookie
    packet += [99, 130, 83, 99]
    # dhcp message type option (53) but no length byte!
    packet += [53]

    data = pack(str(len(packet))+"B", *packet)
    dp = DhcpBasicPacket()
    # This should not raise an IndexError
    dp.DecodePacket(data)

def test_malformed_packet_missing_length_unknown_option():
    packet = [0] * 236
    # magic cookie
    packet += [99, 130, 83, 99]
    # some unknown option but no length byte
    packet += [153]

    data = pack(str(len(packet))+"B", *packet)
    dp = DhcpBasicPacket()
    # This should not raise an IndexError
    dp.DecodePacket(data)
