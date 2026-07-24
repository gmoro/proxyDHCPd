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

def test_daemon_umask_secure():
    import sys
    import os
    from unittest import mock
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Windows")

    with mock.patch('proxydhcpd.cli.DHCPD'), \
         mock.patch('proxydhcpd.cli.ProxyDHCPD'), \
         mock.patch('socket.socket'), \
         mock.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         mock.patch('os.access', return_value=True), \
         mock.patch('os.fork') as mock_fork, \
         mock.patch('os.chdir'), \
         mock.patch('os.setsid'), \
         mock.patch('os.umask') as mock_umask, \
         mock.patch('sys.exit', side_effect=SystemExit), \
         mock.patch('proxydhcpd.net.get_dev_name', return_value='eth0'):

        # mock_fork returns 0 on first call, raises SystemExit on second
        mock_fork.side_effect = [0, SystemExit]

        from proxydhcpd.cli import main

        try:
            main()
        except SystemExit:
            pass

        mock_umask.assert_called_once_with(0o022)
