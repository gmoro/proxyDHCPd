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
from unittest.mock import patch

def test_daemonize_umask():
    if sys.platform == 'win32':
        pytest.skip("Daemonization is not supported on Windows")

    # Mock the various system calls
    with patch('os.fork') as mock_fork, \
         patch('os.setsid') as mock_setsid, \
         patch('os.chdir') as mock_chdir, \
         patch('os.umask') as mock_umask, \
         patch('sys.exit') as mock_exit, \
         patch('os.access', return_value=True), \
         patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         patch('socket.socket'), \
         patch('proxydhcpd.cli.DHCPD'), \
         patch('proxydhcpd.cli.ProxyDHCPD'):

        # mock_fork will be called twice.
        # Let's make it return 0 for both to simulate the child process in double fork.
        mock_fork.side_effect = [0, 0]

        # Import the main loop of the cli, but don't let it block
        from proxydhcpd.cli import main

        # When main executes, it will spawn threads and then sleep. Let's make sleep raise SystemExit to stop the loop.
        with patch('time.sleep', side_effect=SystemExit):
            try:
                main()
            except SystemExit:
                pass

        # Assert umask was called with 0o022
        mock_umask.assert_called_with(0o022)
