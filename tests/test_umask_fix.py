import sys
import os
import unittest
from unittest.mock import patch

# Mock setup for cli.py
class TestUmaskFix(unittest.TestCase):
    @patch('sys.exit')
    @patch('os.fork')
    @patch('os.chdir')
    @patch('os.setsid')
    @patch('os.umask')
    @patch('proxydhcpd.cli.DHCPD')
    @patch('proxydhcpd.cli.ProxyDHCPD')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('os.access', return_value=True)
    def test_daemon_umask(self, mock_access, mock_parse_args, mock_proxydhcpd, mock_dhcpd,
                          mock_umask, mock_setsid, mock_chdir, mock_fork, mock_exit):

        # We need a mock args object
        class MockArgs:
            config = '/etc/proxydhcpd/proxy.ini'
            daemon = True
            proxy_only = False

        mock_parse_args.return_value = MockArgs()

        # We simulate the first fork returning 0 (child), and the second fork raising an OSError
        # or just let it return 0 for both forks but make sure we break out of the infinite loop.
        # However, cli.py loops only if proxyserver and server have loops.
        # Let's set loop=False on the mocks to avoid hanging.

        mock_dhcpd_instance = mock_dhcpd.return_value
        mock_dhcpd_instance.loop = False

        mock_proxydhcpd_instance = mock_proxydhcpd.return_value
        mock_proxydhcpd_instance.loop = False

        mock_fork.side_effect = [0, 0] # child, child

        # sys.platform needs to be linux, let's mock it if needed, but it should be ok
        if sys.platform == 'win32':
            self.skipTest("Daemonization is not tested on win32")

        from proxydhcpd.cli import main

        try:
            main()
        except SystemExit:
            pass

        # Verify that os.umask was called with 0o022
        mock_umask.assert_called_once_with(0o022)

if __name__ == '__main__':
    unittest.main()
