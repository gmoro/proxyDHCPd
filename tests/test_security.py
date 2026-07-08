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

def test_daemon_umask():
    # Test that daemonization uses a secure umask
    # Check if we are on a platform that supports daemonization
    if sys.platform == "win32":
        pytest.skip("Daemonization is not supported on Windows")

    from proxydhcpd.cli import main
    import proxydhcpd.cli

    # We need to mock os.fork, os.umask, os.setsid, os.chdir, sys.exit
    # as well as network utilities and config loading to prevent actual daemonization

    fork_mock_side_effect = [0, SystemExit] # First fork returns 0 (child), second raises SystemExit to stop test

    with patch('os.fork', side_effect=fork_mock_side_effect) as mock_fork, \
         patch('os.umask') as mock_umask, \
         patch('os.setsid'), \
         patch('os.chdir'), \
         patch('sys.exit', side_effect=SystemExit), \
         patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         patch('os.access', return_value=True), \
         patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         patch('socket.socket'):

        try:
            main()
        except SystemExit:
            pass

        mock_umask.assert_called_with(0o022)
