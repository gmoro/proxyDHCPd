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

def test_daemon_umask_is_secure():
    if sys.platform == 'win32':
        pytest.skip("Daemonization is not supported on Windows")

    with patch('proxydhcpd.cli.os.fork', side_effect=[0, 0]) as mock_fork, \
         patch('proxydhcpd.cli.os.chdir') as mock_chdir, \
         patch('proxydhcpd.cli.os.setsid') as mock_setsid, \
         patch('proxydhcpd.cli.os.umask') as mock_umask, \
         patch('proxydhcpd.cli.sys.exit', side_effect=SystemExit) as mock_exit, \
         patch('proxydhcpd.cli.socket.socket'), \
         patch('proxydhcpd.cli.DHCPD'), \
         patch('proxydhcpd.cli.ProxyDHCPD'), \
         patch('proxydhcpd.cli.os.access', return_value=True), \
         patch('proxydhcpd.cli.time.sleep', side_effect=SystemExit), \
         patch('proxydhcpd.cli.sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']):

        from proxydhcpd.cli import main

        try:
            main()
        except SystemExit:
            pass

        mock_umask.assert_called_once_with(0o022)
