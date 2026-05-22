import sys
import os
import unittest
from unittest.mock import patch

from proxydhcpd.cli import main

class TestUmaskFix(unittest.TestCase):
    @patch('proxydhcpd.cli.os.umask')
    @patch('proxydhcpd.cli.os.fork')
    @patch('proxydhcpd.cli.sys.exit')
    @patch('proxydhcpd.cli.os.setsid')
    @patch('proxydhcpd.cli.os.chdir')
    @patch('proxydhcpd.cli.sys.platform', 'linux')
    @patch('proxydhcpd.cli.DHCPD')
    @patch('proxydhcpd.cli.ProxyDHCPD')
    @patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
    @patch('proxydhcpd.cli.os.access')
    def test_daemon_umask_is_secure(
        self, mock_access, mock_parse_args, mock_proxy_dhcpd, mock_dhcpd,
        mock_chdir, mock_setsid, mock_exit, mock_fork, mock_umask
    ):
        """
        Verify that os.umask is called with 0o022 when daemonizing,
        instead of 0, to prevent world-writable files.
        """
        # Mock CLI arguments
        class MockArgs:
            config = '/etc/proxydhcpd/proxy.ini'
            daemon = True
            proxy_only = False
        mock_parse_args.return_value = MockArgs()

        mock_access.return_value = True

        # mock_fork to return 0 on first call (simulate child), and raise SystemExit on second call to stop the infinite loop
        def fork_side_effect():
            if mock_fork.call_count == 1:
                return 0
            else:
                raise SystemExit(0)

        mock_fork.side_effect = fork_side_effect
        mock_exit.side_effect = SystemExit(0)

        # When main is executed and attempts to run as a daemon
        try:
            main()
        except SystemExit:
            pass

        # We assert umask was called with 0o022
        mock_umask.assert_called_with(0o022)

if __name__ == "__main__":
    unittest.main()
