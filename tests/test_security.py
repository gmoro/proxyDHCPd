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
from unittest import mock
import proxydhcpd.cli

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
def test_daemon_uses_secure_umask():
    with mock.patch('os.fork') as mock_fork, \
         mock.patch('os.setsid'), \
         mock.patch('os.chdir'), \
         mock.patch('os.umask') as mock_umask, \
         mock.patch('sys.exit') as mock_exit, \
         mock.patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         mock.patch('proxydhcpd.cli.DHCPD'), \
         mock.patch('proxydhcpd.cli.ProxyDHCPD'):

        def fork_side_effect():
            if mock_fork.call_count == 1:
                return 0
            raise SystemExit

        mock_fork.side_effect = fork_side_effect
        mock_exit.side_effect = SystemExit

        with mock.patch.object(sys, 'argv', ['proxydhcpd', '-d', '-c', 'proxy.ini']):
            with mock.patch('os.access', return_value=True):
                try:
                    proxydhcpd.cli.main()
                except SystemExit:
                    pass

        mock_umask.assert_called_once_with(0o022)
