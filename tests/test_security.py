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

def test_daemon_umask(mocker):
    import sys
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Windows")

    mocker.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])
    mocker.patch('socket.socket')
    mocker.patch('proxydhcpd.cli.DHCPD')
    mocker.patch('proxydhcpd.cli.ProxyDHCPD')
    mocker.patch('os.fork', side_effect=[0, 0])
    mocker.patch('os.chdir')
    mocker.patch('os.setsid')
    mock_umask = mocker.patch('os.umask')
    mocker.patch('time.sleep', side_effect=SystemExit)
    mocker.patch('sys.exit', side_effect=SystemExit)

    from proxydhcpd.cli import main
    try:
        main()
    except SystemExit:
        pass

    mock_umask.assert_called_with(0o022)
