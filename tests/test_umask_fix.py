import unittest
from unittest.mock import patch
import sys
import os

from proxydhcpd.cli import main

class TestUmaskFix(unittest.TestCase):
    @patch('proxydhcpd.cli.os.umask')
    @patch('proxydhcpd.cli.os.setsid')
    @patch('proxydhcpd.cli.os.chdir')
    @patch('proxydhcpd.cli.os.fork')
    @patch('proxydhcpd.cli.sys.exit', side_effect=SystemExit)
    @patch('proxydhcpd.cli.sys.argv', ['proxydhcpd', '-d'])
    @patch('proxydhcpd.cli.os.access')
    @patch('proxydhcpd.cli.DHCPD')
    @patch('proxydhcpd.cli.ProxyDHCPD')
    def test_umask_is_secure(self, mock_proxy_dhcpd, mock_dhcpd, mock_access, mock_exit, mock_fork, mock_chdir, mock_setsid, mock_umask):
        # We need to test the daemon path
        mock_access.return_value = True

        # Prevent actually exiting or forking
        # Simulate fork 1 returning 0 (child process)
        # Simulate fork 2 throwing OSError to break out of the loop and not spawn threads
        mock_fork.side_effect = [0, OSError(1, "Mocked OSError")]

        # Call main, which will eventually hit the fork code
        with self.assertRaises(SystemExit):
            main()

        # Verify umask was called with 0o022
        mock_umask.assert_called_once_with(0o022)

if __name__ == '__main__':
    unittest.main()
