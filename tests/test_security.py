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
from unittest.mock import patch

def test_daemon_umask_is_secure():
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Win32")

    with patch('os.fork') as mock_fork, \
         patch('os.setsid') as mock_setsid, \
         patch('os.chdir') as mock_chdir, \
         patch('os.umask') as mock_umask, \
         patch('sys.exit') as mock_exit, \
         patch('socket.socket'), \
         patch('os.access', return_value=True), \
         patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         patch('proxydhcpd.cli.DHCPD'), \
         patch('proxydhcpd.cli.ProxyDHCPD'):

        # Mock sys.argv
        with patch.object(sys, 'argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):
            # First fork returns 0 (child), second fork calls sys.exit(0)
            mock_fork.side_effect = [0, 1]
            mock_exit.side_effect = SystemExit()

            from proxydhcpd.cli import main

            try:
                main()
            except SystemExit:
                pass

            mock_umask.assert_called_with(0o022)
