import os
import sys
import pytest
from unittest.mock import patch, MagicMock

@patch('proxydhcpd.cli.os.fork')
@patch('proxydhcpd.cli.os.setsid')
@patch('proxydhcpd.cli.os.chdir')
@patch('proxydhcpd.cli.os.umask')
@patch('proxydhcpd.cli.sys.exit')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.setup_global_logger')
@patch('proxydhcpd.cli.os.access')
@patch('proxydhcpd.cli.threading.Thread')
def test_secure_umask(mock_thread, mock_access, mock_logger, mock_args, mock_proxydhcpd, mock_dhcpd, mock_exit, mock_umask, mock_chdir, mock_setsid, mock_fork):
    from proxydhcpd.cli import main

    # Simulate command-line arguments to trigger daemon mode
    args = MagicMock()
    args.config = 'dummy.ini'
    args.daemon = True
    args.proxy_only = False
    mock_args.return_value = args

    # Mock os.access to return True
    mock_access.return_value = True

    # First fork returns 0 (child), second fork returns 0 (child)
    mock_fork.side_effect = [0, 0]

    # Prevent infinite loop by simulating sys.exit or a similar mechanism if necessary,
    # but sys.exit is already mocked.  To break the main loop, we need to make sure the loop condition is false.
    # The loop runs while (proxyserver and proxyserver.loop) or (server and server.loop).
    mock_proxydhcpd.return_value.loop = False
    mock_dhcpd.return_value.loop = False

    main()

    # Verify os.umask was called with 0o022
    mock_umask.assert_called_once_with(0o022)
