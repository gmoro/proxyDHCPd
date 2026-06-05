import pytest
import sys
from unittest.mock import patch, MagicMock

from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie
from proxydhcpd.cli import main

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

@patch('os.fork')
@patch('os.chdir')
@patch('os.setsid')
@patch('os.umask')
@patch('sys.exit')
@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.setup_global_logger')
@patch('proxydhcpd.cli.os.access')
@patch('proxydhcpd.cli.ProxyDHCPD')
def test_daemon_secure_umask(mock_proxydhcpd, mock_access, mock_setup_logger, mock_parse_args,
                             mock_exit, mock_umask, mock_setsid, mock_chdir, mock_fork):
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Windows")

    mock_args = MagicMock()
    mock_args.config = '/etc/proxydhcpd/proxy.ini'
    mock_args.daemon = True
    mock_args.proxy_only = True # simplify testing by skipping full DHCPD
    mock_parse_args.return_value = mock_args
    mock_access.return_value = True

    # fork() returns 0 on the first call to simulate the child,
    # then on the second call, we just raise SystemExit to stop the test from hanging
    # or proceeding further.
    def fork_side_effect():
        if mock_fork.call_count == 1:
            return 0
        raise SystemExit(0)
    mock_fork.side_effect = fork_side_effect

    mock_exit.side_effect = SystemExit(0)

    try:
        main()
    except SystemExit:
        pass

    # Verify os.umask was called with 0o022, not 0
    mock_umask.assert_called_with(0o022)
