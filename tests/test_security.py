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

import os
import sys
from unittest.mock import patch, MagicMock

@patch('os.fork')
@patch('os.chdir')
@patch('os.setsid')
@patch('os.umask')
@patch('os.access')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
@patch('socket.socket')
def test_daemon_secure_umask(mock_socket, mock_proxy_dhcpd, mock_dhcpd, mock_access, mock_umask, mock_setsid, mock_chdir, mock_fork):
    """Test that the daemonization process uses a secure umask."""
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on win32")

    from proxydhcpd.cli import main

    # Simulate sys.argv
    test_args = ['proxydhcpd', '-c', 'proxy.ini', '-d']

    # Mock os.access to True so config check passes
    mock_access.return_value = True

    # Simulate fork: return 0 for both forks to reach the daemon code
    mock_fork.side_effect = [0, 0]

    # Break out of the infinite loop in main() by raising SystemExit when threading.Thread.start is called,
    # or by patching time.sleep
    with patch('sys.argv', test_args):
        with patch('time.sleep', side_effect=SystemExit):
            try:
                main()
            except SystemExit:
                pass

    # Verify os.umask was called with 0o022
    mock_umask.assert_called_once_with(0o022)
