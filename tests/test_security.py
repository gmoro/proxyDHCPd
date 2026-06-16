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
import unittest.mock as mock

def test_daemon_umask():
    # Test that daemonizing uses a secure umask
    from proxydhcpd.cli import main

    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Win32")

    # Mock the command line arguments to run as a proxy-only daemon
    with mock.patch('sys.argv', ['proxydhcpd', '--daemon', '--proxy-only', '--config', 'proxy.ini']):
        # Mock os functions to prevent actual daemonization and side effects
        with mock.patch('os.fork', side_effect=[0, SystemExit(0)]), \
             mock.patch('os.chdir'), \
             mock.patch('os.setsid'), \
             mock.patch('os.umask') as mock_umask, \
             mock.patch('sys.exit', side_effect=SystemExit), \
             mock.patch('os.access', return_value=True), \
             mock.patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
             mock.patch('proxydhcpd.dhcpd.ProxyDHCPD', autospec=True):

            try:
                main()
            except SystemExit:
                pass

            # Assert that umask was called with 0o022 (not 0)
            mock_umask.assert_called_once_with(0o022)
