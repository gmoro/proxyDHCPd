import pytest
from proxydhcpd.dhcplib.dhcp_packet import DhcpPacket
from proxydhcpd.dhcplib.dhcp_constants import MagicCookie

def test_decode_packet_out_of_bounds_known():
    packet = DhcpPacket()
    # Create a payload with MagicCookie and a trailing known option type without length
    payload = [0] * 236 + MagicCookie + [53]
    # This should not raise an IndexError
    packet.DecodePacket(bytes(payload))

def test_daemon_secure_umask(mocker):
    import sys
    if sys.platform == 'win32':
        pytest.skip("Daemonization not supported on Windows")

    mocker.patch('socket.socket')
    mocker.patch('proxydhcpd.cli.DHCPD')
    mocker.patch('proxydhcpd.cli.ProxyDHCPD')
    mocker.patch('sys.argv', ['proxydhcpd', '-c', 'proxy.ini', '-d'])

    mock_fork = mocker.patch('os.fork', side_effect=[0, 0])
    mock_chdir = mocker.patch('os.chdir')
    mock_setsid = mocker.patch('os.setsid')
    mock_umask = mocker.patch('os.umask')
    mock_exit = mocker.patch('sys.exit', side_effect=SystemExit)

    mocker.patch('os.access', return_value=True)
    mocker.patch('proxydhcpd.net.get_dev_name', return_value='eth0')

    # Break the infinite loop by making time.sleep raise SystemExit
    mocker.patch('time.sleep', side_effect=SystemExit)

    from proxydhcpd.cli import main as cli_main

    with pytest.raises(SystemExit):
        cli_main()

    mock_umask.assert_called_with(0o022)

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
