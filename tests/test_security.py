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

import sys
import os
from unittest import mock
from proxydhcpd import cli

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@mock.patch('proxydhcpd.cli.os.fork', side_effect=[0, 0])
@mock.patch('proxydhcpd.cli.os.chdir')
@mock.patch('proxydhcpd.cli.os.setsid')
@mock.patch('proxydhcpd.cli.os.umask')
@mock.patch('proxydhcpd.cli.sys.exit', side_effect=SystemExit)
@mock.patch('proxydhcpd.cli.time.sleep', side_effect=SystemExit)
@mock.patch('proxydhcpd.cli.os.access', return_value=True)
@mock.patch('proxydhcpd.cli.DHCPD')
@mock.patch('proxydhcpd.cli.ProxyDHCPD')
@mock.patch('proxydhcpd.cli.socket.socket')
def test_daemonize_umask(mock_socket, mock_proxy, mock_dhcpd, mock_access, mock_sleep, mock_exit, mock_umask, mock_setsid, mock_chdir, mock_fork):
    with mock.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):
        try:
            cli.main()
        except SystemExit:
            pass
    mock_umask.assert_called_with(0o022)
