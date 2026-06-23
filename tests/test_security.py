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
import unittest.mock as mock

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization not supported on Windows")
def test_daemon_uses_secure_umask():
    from proxydhcpd.cli import main

    # Mock network utilities and config check to pass initial setup
    with mock.patch('os.access', return_value=True), \
         mock.patch('proxydhcpd.proxyconfig.parse_config.__new__'), \
         mock.patch('proxydhcpd.net.get_dev_name', return_value='eth0'), \
         mock.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         mock.patch('proxydhcpd.cli.DHCPD'), \
         mock.patch('proxydhcpd.cli.ProxyDHCPD'), \
         mock.patch('os.chdir'), \
         mock.patch('os.setsid'), \
         mock.patch('sys.exit', side_effect=SystemExit) as mock_exit:

        # Mock os.fork to simulate double fork behavior and prevent infinite loops
        def fork_side_effect():
            fork_side_effect.call_count += 1
            if fork_side_effect.call_count == 1:
                return 0 # Child of first fork
            else:
                raise SystemExit() # Stop after second fork to avoid hanging

        fork_side_effect.call_count = 0

        with mock.patch('os.fork', side_effect=fork_side_effect), \
             mock.patch('os.umask') as mock_umask:

            try:
                main()
            except SystemExit:
                pass

            # Ensure umask was called with the secure value 0o022 (18)
            mock_umask.assert_called_with(0o022)
