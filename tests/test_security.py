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
import socket
from unittest import mock
import pytest

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@mock.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
@mock.patch('os.fork')
@mock.patch('os.setsid')
@mock.patch('os.chdir')
@mock.patch('os.umask')
@mock.patch('sys.exit')
@mock.patch('os.access')
@mock.patch('socket.socket')
@mock.patch('proxydhcpd.cli.DHCPD')
@mock.patch('proxydhcpd.cli.ProxyDHCPD')
@mock.patch('proxydhcpd.net.get_dev_name')
def test_daemonization_secure_umask(mock_get_dev_name, mock_proxy_dhcpd, mock_dhcpd, mock_socket, mock_access, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    mock_access.return_value = True
    mock_get_dev_name.return_value = 'eth0'

    # First fork returns 0 (child), second fork raises SystemExit to stop infinite loop
    mock_fork.side_effect = [0, SystemExit]
    mock_exit.side_effect = SystemExit

    from proxydhcpd.cli import main

    with pytest.raises(SystemExit):
        main()

    mock_umask.assert_called_once_with(0o022)
