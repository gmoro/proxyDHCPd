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
from unittest.mock import patch, MagicMock

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@patch('os.fork')
@patch('os.umask')
@patch('os.chdir')
@patch('os.setsid')
@patch('sys.exit')
@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
def test_daemon_umask(mock_proxydhcpd, mock_dhcpd, mock_parse_args, mock_exit, mock_setsid, mock_chdir, mock_umask, mock_fork):
    from proxydhcpd.cli import main
    import os

    # Setup mocks
    mock_args = MagicMock()
    mock_args.config = '/etc/proxydhcpd/proxy.ini'
    mock_args.daemon = True
    mock_args.proxy_only = False
    mock_parse_args.return_value = mock_args

    # Mock os.fork to return 0 on the first call (child), and raise SystemExit on the second
    def fork_side_effect():
        if mock_fork.call_count == 1:
            return 0
        else:
            raise SystemExit(0)
    mock_fork.side_effect = fork_side_effect
    mock_exit.side_effect = SystemExit(0)

    # Mock os.access to return True
    with patch('os.access', return_value=True):
        try:
            main()
        except SystemExit:
            pass

    # Verify os.umask was called with 0o022
    mock_umask.assert_called_once_with(0o022)
