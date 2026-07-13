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

def test_daemon_umask_secure():
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on win32")

    from proxydhcpd import cli

    with patch('os.fork') as mock_fork, \
         patch('os.chdir') as mock_chdir, \
         patch('os.setsid') as mock_setsid, \
         patch('os.umask') as mock_umask, \
         patch('sys.exit') as mock_exit, \
         patch('os.access', return_value=True), \
         patch('socket.socket'), \
         patch('proxydhcpd.cli.DHCPD'), \
         patch('proxydhcpd.cli.ProxyDHCPD'), \
         patch.object(sys, 'argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):

        mock_fork.side_effect = [0, SystemExit]
        mock_exit.side_effect = SystemExit

        with patch('time.sleep', side_effect=KeyboardInterrupt):
            try:
                cli.main()
            except SystemExit:
                pass
            mock_umask.assert_called_once_with(0o022)
