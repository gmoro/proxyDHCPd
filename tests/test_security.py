import pytest
import sys
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

@pytest.mark.skipif(sys.platform == 'win32', reason="Daemonization is not supported on Windows")
def test_secure_umask_daemonization():
    import sys
    import os
    from unittest.mock import patch
    import proxydhcpd.cli

    # Track calls to fork to exit on the second one
    def fork_side_effect():
        fork_side_effect.calls += 1
        if fork_side_effect.calls == 1:
            return 0  # First child
        else:
            raise SystemExit(0)  # Simulate sys.exit on second parent to stop daemonization flow

    fork_side_effect.calls = 0

    with patch('os.fork', side_effect=fork_side_effect), \
         patch('sys.exit', side_effect=SystemExit), \
         patch('socket.socket'), \
         patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d']), \
         patch('os.setsid'), \
         patch('os.chdir'), \
         patch('os.umask') as mock_umask, \
         patch('os.access', return_value=True), \
         patch('proxydhcpd.net.get_dev_name', return_value='eth0'):

        try:
            proxydhcpd.cli.main()
        except SystemExit:
            pass  # Expected when simulating exit

        # Verify that umask was set securely
        mock_umask.assert_called_with(0o022)
