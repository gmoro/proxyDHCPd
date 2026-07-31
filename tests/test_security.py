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
from unittest.mock import patch

def mock_fork_side_effect():
    mock_fork_side_effect.calls += 1
    if mock_fork_side_effect.calls == 1:
        return 0
    raise SystemExit
mock_fork_side_effect.calls = 0

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
@patch('os.fork', side_effect=mock_fork_side_effect)
@patch('os.setsid')
@patch('os.chdir')
@patch('os.umask')
@patch('sys.exit', side_effect=SystemExit)
@patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
@patch('os.access', return_value=True)
@patch('socket.socket')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
@patch('proxydhcpd.net.get_dev_name', return_value='eth0')
def test_daemon_umask_secure(mock_get_dev_name, mock_proxy, mock_dhcpd, mock_socket, mock_access, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main
    try:
        main()
    except SystemExit:
        pass
    mock_umask.assert_called_once_with(0o022)
