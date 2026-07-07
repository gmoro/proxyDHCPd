import os
import sys
import unittest
from unittest import mock

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

def test_daemon_umask():
    if sys.platform == 'win32':
        pytest.skip("Daemonization is not supported on Windows")

    # Mock the various system calls
    with mock.patch('os.fork') as mock_fork, \
         mock.patch('sys.exit') as mock_exit, \
         mock.patch('os.umask') as mock_umask, \
         mock.patch('os.setsid') as mock_setsid, \
         mock.patch('os.chdir') as mock_chdir, \
         mock.patch('os.access', return_value=True), \
         mock.patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         mock.patch('socket.socket'), \
         mock.patch('proxydhcpd.cli.DHCPD'), \
         mock.patch('proxydhcpd.cli.ProxyDHCPD'):

        # Prevent entering the infinite loop by making fork return 0 first, then raise SystemExit
        mock_fork.side_effect = [0, SystemExit()]
        mock_exit.side_effect = SystemExit()

        with mock.patch.object(sys, 'argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):
            from proxydhcpd.cli import main

            try:
                main()
            except SystemExit:
                pass

            # Assert umask was called with 0o022
            mock_umask.assert_called_once_with(0o022)
