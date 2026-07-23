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

import os
import sys
from unittest import mock
import proxydhcpd.cli

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@mock.patch('proxydhcpd.cli.DHCPD')
@mock.patch('proxydhcpd.cli.ProxyDHCPD')
@mock.patch('socket.socket')
@mock.patch('os.access')
@mock.patch('os.fork')
@mock.patch('os.chdir')
@mock.patch('os.setsid')
@mock.patch('os.umask')
@mock.patch('sys.exit')
def test_secure_umask_on_daemonize(mock_exit, mock_umask, mock_setsid, mock_chdir, mock_fork, mock_access, mock_socket, mock_proxydhcpd, mock_dhcpd):
    mock_access.return_value = True

    def fork_side_effect():
        if mock_fork.call_count == 1:
            return 0
        raise SystemExit(0)

    mock_fork.side_effect = fork_side_effect
    mock_exit.side_effect = SystemExit

    with mock.patch.object(sys, 'argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):
        with pytest.raises(SystemExit):
            proxydhcpd.cli.main()

    mock_umask.assert_called_once_with(0o022)
