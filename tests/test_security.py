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

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@patch('os.fork')
@patch('os.setsid')
@patch('os.chdir')
@patch('os.umask')
@patch('sys.exit')
@patch('os.access')
@patch('proxydhcpd.cli.ProxyDHCPD')
def test_daemon_umask(mock_proxydhcpd, mock_access, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    mock_fork.side_effect = [0, SystemExit]
    mock_exit.side_effect = SystemExit
    mock_access.return_value = True

    from proxydhcpd.cli import main

    with patch('sys.argv', ['proxydhcpd', '-c', 'dummy.ini', '-d', '-p']):
        with pytest.raises(SystemExit):
            main()

    mock_umask.assert_called_with(0o022)
