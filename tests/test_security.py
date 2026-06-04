import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie

def test_decode_packet_out_of_bounds_known():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing known option type without length
    payload = [0] * 236 + MagicCookie + [53]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

import sys
from unittest.mock import patch, MagicMock

@patch('proxydhcpd.cli.os.fork')
@patch('proxydhcpd.cli.os.setsid')
@patch('proxydhcpd.cli.os.chdir')
@patch('proxydhcpd.cli.os.umask')
@patch('proxydhcpd.cli.sys.exit')
@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.os.access', return_value=True)
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
def test_daemon_secure_umask(mock_proxy, mock_dhcpd, mock_access, mock_parse_args, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main

    # Setup mock arguments
    args = MagicMock()
    args.config = 'dummy.ini'
    args.daemon = True
    args.proxy_only = False
    mock_parse_args.return_value = args

    # Mock sys.platform to bypass win32 check
    with patch('sys.platform', 'linux'):
        # Mock os.fork to simulate parent exiting and child continuing
        # First call returns 0 (child), second call raises SystemExit to stop the test
        mock_fork.side_effect = [0, SystemExit("Stop test after second fork")]
        mock_exit.side_effect = SystemExit("Mock Exit")

        try:
            main()
        except SystemExit as e:
            if str(e) != "Stop test after second fork":
                raise

        # Verify umask was called with 0o022
        mock_umask.assert_called_once_with(0o022)

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
