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
import unittest.mock as mock

def test_secure_umask_on_daemonize():
    if sys.platform == 'win32':
        pytest.skip("Daemonization is not supported on Windows")

    # Mock the necessary functions to prevent test hanging and side effects
    with mock.patch('os.fork') as mock_fork, \
         mock.patch('os.chdir') as mock_chdir, \
         mock.patch('os.setsid') as mock_setsid, \
         mock.patch('os.umask') as mock_umask, \
         mock.patch('os.access', return_value=True) as mock_access, \
         mock.patch('sys.exit', side_effect=SystemExit) as mock_exit, \
         mock.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         mock.patch('socket.socket'), \
         mock.patch('proxydhcpd.cli.DHCPD') as mock_dhcpd, \
         mock.patch('proxydhcpd.cli.ProxyDHCPD') as mock_proxydhcpd:

        # First fork returns 0 (child), second fork returns 0 (child) but we want to exit after second fork setup
        # Or better yet, we simulate parent in second fork to exit, or child to exit immediately.
        # Actually, in cli.py, the second fork parent exits, child proceeds.
        # We will make second fork raise SystemExit to stop the script.

        # mock_fork side effects:
        # 1st call: returns 0 (acts as first child)
        # 2nd call: returns 0 (acts as second child) but raises SystemExit to stop the loop execution

        def fork_side_effect():
            if mock_fork.call_count == 1:
                return 0
            else:
                # 2nd call
                raise SystemExit()

        mock_fork.side_effect = fork_side_effect

        from proxydhcpd.cli import main

        try:
            main()
        except SystemExit:
            pass

        mock_chdir.assert_called_with("/")
        mock_setsid.assert_called_once()
        mock_umask.assert_called_with(0o022)
