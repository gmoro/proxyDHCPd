import pytest
import sys
import os
from unittest.mock import patch
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie
from proxydhcpd.cli import main

def test_secure_umask_daemonization():
    if sys.platform == "win32":
        pytest.skip("Daemonization not supported on Windows")

    with patch("os.fork", side_effect=[0, 0]) as mock_fork, \
         patch("os.setsid") as mock_setsid, \
         patch("os.chdir") as mock_chdir, \
         patch("os.umask") as mock_umask, \
         patch("proxydhcpd.cli.DHCPD") as mock_dhcpd, \
         patch("proxydhcpd.cli.ProxyDHCPD") as mock_proxydhcpd, \
         patch("proxydhcpd.net.get_dev_name", return_value="eth0"), \
         patch("os.access", return_value=True), \
         patch("socket.socket"), \
         patch("sys.argv", ["proxydhcpd", "-c", "proxy.ini", "-d"]), \
         patch("time.sleep", side_effect=SystemExit):

        try:
            main()
        except SystemExit:
            pass

        mock_umask.assert_called_with(0o022)


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
