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
@patch('proxydhcpd.cli.os.fork')
@patch('proxydhcpd.cli.os.setsid')
@patch('proxydhcpd.cli.os.chdir')
@patch('proxydhcpd.cli.os.umask')
@patch('proxydhcpd.cli.sys.exit')
@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.setup_global_logger')
@patch('proxydhcpd.cli.os.access')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
def test_daemon_umask_is_secure(mock_proxydhcpd, mock_dhcpd, mock_access, mock_logger, mock_args, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main

    # Configure mock args to run as daemon
    args = MagicMock()
    args.config = 'dummy.ini'
    args.daemon = True
    args.proxy_only = False
    mock_args.return_value = args

    mock_access.return_value = True

    # Make os.fork return 0 on first call, raise SystemExit on second to break the flow safely
    mock_fork.side_effect = [0, SystemExit("Stop execution for test")]
    mock_exit.side_effect = SystemExit("Normal exit")

    with pytest.raises(SystemExit):
        main()

    mock_umask.assert_called_once_with(0o022)
