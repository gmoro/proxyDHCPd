import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_basic_packet import DhcpBasicPacket

def test_dhcppacket_str():
    p = DhcpPacket()
    p.packet_data = [0] * 240
    p.packet_data[0] = 1 # op
    # Make hwmac
    p.str()

test_dhcppacket_str()
