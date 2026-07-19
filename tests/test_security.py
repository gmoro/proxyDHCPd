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

@patch('os.fork')
@patch('os.umask')
@patch('os.setsid')
@patch('os.chdir')
@patch('sys.exit')
@patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
@patch('os.access', return_value=True)
@patch('proxydhcpd.net.get_dev_name', return_value='eth0')
@patch('socket.socket')
def test_secure_umask_on_daemonize(mock_socket, mock_get_dev_name, mock_os_access, mock_exit, mock_chdir, mock_setsid, mock_umask, mock_fork):
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on win32")

    def fork_side_effect():
        fork_side_effect.call_count = getattr(fork_side_effect, 'call_count', 0) + 1
        if fork_side_effect.call_count == 1:
            return 0  # First fork, child process
        else:
            raise SystemExit  # Prevent second fork loop

    mock_fork.side_effect = fork_side_effect
    mock_exit.side_effect = SystemExit

    from proxydhcpd.cli import main
    try:
        main()
    except SystemExit:
        pass

    mock_umask.assert_called_once_with(0o022)
