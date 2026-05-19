import pytest
import sys
import os
from unittest.mock import patch

from proxydhcpd.cli import main

@patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
@patch('proxydhcpd.cli.os.fork')
@patch('proxydhcpd.cli.os.umask')
@patch('proxydhcpd.cli.os.setsid')
@patch('proxydhcpd.cli.os.chdir')
@patch('proxydhcpd.cli.os.access')
@patch('proxydhcpd.cli.DHCPD')
@patch('proxydhcpd.cli.ProxyDHCPD')
@patch('proxydhcpd.cli.sys.exit')
@patch('proxydhcpd.cli.sys.platform', 'linux')
def test_umask_secure(mock_exit, mock_proxy_dhcpd, mock_dhcpd, mock_access, mock_chdir, mock_setsid, mock_umask, mock_fork, mock_args):
    # Setup mock arguments
    class Args:
        config = '/etc/proxydhcpd/proxy.ini'
        daemon = True
        proxy_only = False

    mock_args.return_value = Args()
    mock_access.return_value = True

    # Avoid infinite loop or actual exiting when mocking fork/exit
    # Let first fork return 0 (child), second fork return 0 (child)
    mock_fork.side_effect = [0, 0]

    # sys.exit should raise SystemExit so we can stop execution
    mock_exit.side_effect = SystemExit

    # We need to catch the loop trying to run threads, let's just
    # make the mock proxy server have no loop.
    mock_proxy_inst = mock_proxy_dhcpd.return_value
    mock_proxy_inst.loop = False
    mock_dhcpd_inst = mock_dhcpd.return_value
    mock_dhcpd_inst.loop = False

    # Execute main
    main()

    # Verify os.umask was called with the secure value (0o022 instead of 0)
    mock_umask.assert_called_once_with(0o022)
