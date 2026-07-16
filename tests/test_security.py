import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie

def test_decode_packet_out_of_bounds_known():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing known option type without length
    payload = [0] * 236 + MagicCookie + [53]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

import sys
import os
import socket
from unittest.mock import patch, MagicMock

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization is not supported on Windows")
@patch('os.fork')
@patch('os.setsid')
@patch('os.chdir')
@patch('os.umask')
@patch('sys.exit')
@patch('socket.socket')
@patch('os.access', return_value=True)
@patch('proxydhcpd.net.get_dev_name', return_value='eth0')
@patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
def test_daemon_umask(mock_get_dev_name, mock_access, mock_socket, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main

    # Simulate first fork returning 0 (child), second fork raising SystemExit to stop infinite loop
    mock_fork.side_effect = [0, SystemExit]
    mock_exit.side_effect = SystemExit

    try:
        main()
    except SystemExit:
        pass

    # Assert umask was called with secure mask
    mock_umask.assert_called_with(0o022)

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
