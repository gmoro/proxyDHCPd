import os
import sys
import unittest
from unittest.mock import patch

from proxydhcpd import cli

class TestUmaskFix(unittest.TestCase):
    @patch('proxydhcpd.cli.os.fork')
    @patch('proxydhcpd.cli.os.umask')
    @patch('proxydhcpd.cli.sys.exit')
    @patch('proxydhcpd.cli.setup_global_logger')
    @patch('proxydhcpd.cli.os.access')
    @patch('proxydhcpd.cli.DHCPD')
    @patch('proxydhcpd.cli.ProxyDHCPD')
    @patch('proxydhcpd.cli.os.setsid')
    @patch('proxydhcpd.cli.os.chdir')
    def test_daemon_umask(self, mock_chdir, mock_setsid, mock_proxydhcpd, mock_dhcpd, mock_access, mock_logger, mock_exit, mock_umask, mock_fork):
        # Setup mocks
        mock_access.return_value = True

        # Simulate child process from fork
        # We need the second fork to exit the main thread to avoid looping forever

        def fork_side_effect():
            fork_side_effect.calls += 1
            if fork_side_effect.calls == 1:
                return 0
            else:
                # Raise an exception to break out of the infinite loop
                raise SystemExit

        fork_side_effect.calls = 0
        mock_fork.side_effect = fork_side_effect

        # Avoid hanging on exit in the mock
        mock_exit.side_effect = SystemExit

        # Set daemon to True
        test_args = ['proxydhcpd', '-d']

        with patch.object(sys, 'argv', test_args):
            try:
                cli.main()
            except SystemExit:
                pass

        # Assert umask was called with 0o022
        mock_umask.assert_called_once_with(0o022)

if __name__ == '__main__':
    unittest.main()
