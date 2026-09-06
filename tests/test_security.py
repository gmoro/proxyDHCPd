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

def test_daemon_secure_umask(mocker):
    if sys.platform == 'win32':
        pytest.skip("Daemonization is not supported on Windows")

    # Mock necessary dependencies
    mocker.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
    mocker.patch('os.fork', side_effect=[0, 0])
    mocker.patch('os.setsid')
    mocker.patch('os.chdir')
    mock_umask = mocker.patch('os.umask')
    mocker.patch('socket.socket')
    mocker.patch('proxydhcpd.cli.DHCPD')
    mocker.patch('proxydhcpd.cli.ProxyDHCPD')
    mocker.patch('sys.exit', side_effect=SystemExit)
    mocker.patch('time.sleep', side_effect=SystemExit)

    # Run the main CLI entry point
    from proxydhcpd.cli import main
    try:
        main()
    except SystemExit:
        pass

    # Verify umask was set securely
    mock_umask.assert_called_with(0o022)
