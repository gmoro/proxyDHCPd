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
from unittest.mock import patch, MagicMock

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@patch('os.fork')
@patch('os.setsid')
@patch('os.chdir')
@patch('os.umask')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
@patch('socket.socket')
@patch('time.sleep')
@patch('os.access')
@patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
@patch('proxydhcpd.net.get_dev_name')
def test_daemon_umask_secure(mock_get_dev_name, mock_access, mock_sleep, mock_socket, mock_proxy, mock_dhcpd, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main

    mock_access.return_value = True
    mock_get_dev_name.return_value = 'eth0'
    mock_sleep.side_effect = SystemExit  # Break out of the infinite while loop
    mock_fork.side_effect = [0, 0]  # First fork child, second fork child

    with pytest.raises(SystemExit):
        main()

    # Verify os.umask was called with restrictive permissions instead of 0
    mock_umask.assert_called_once_with(0o022)
