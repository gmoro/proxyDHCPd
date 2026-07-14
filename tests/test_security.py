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
from unittest.mock import patch, MagicMock

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
@patch('os.access', return_value=True)
@patch('os.fork')
@patch('os.setsid')
@patch('os.chdir')
@patch('os.umask')
@patch('sys.exit')
@patch('socket.socket')
def test_daemonization_secure_umask(mock_socket, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork, mock_access):
    from proxydhcpd.cli import main

    # os.fork gets called twice in the double-fork daemonization process.
    # We want it to simulate the child process in both cases (returning 0).
    # After the second fork, we need to stop the execution to avoid the infinite loop,
    # so we raise SystemExit, simulating a program exit.
    mock_fork.side_effect = [0, SystemExit]
    mock_exit.side_effect = SystemExit

    # We also need to mock network utils used in DHCPD initialization
    with patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         patch('proxydhcpd.net.get_ip_address', return_value='127.0.0.1'):
        try:
            main()
        except SystemExit:
            pass

    mock_umask.assert_called_once_with(0o022)
