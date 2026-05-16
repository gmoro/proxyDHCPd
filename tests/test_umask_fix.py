import os
import sys
import unittest
from unittest.mock import patch
import proxydhcpd.cli

class TestDaemonUmask(unittest.TestCase):
    @patch('os.fork')
    @patch('os.chdir')
    @patch('os.setsid')
    @patch('os.umask')
    @patch('sys.exit')
    @patch('proxydhcpd.cli.argparse.ArgumentParser.parse_args')
    @patch('proxydhcpd.cli.DHCPD')
    @patch('proxydhcpd.cli.ProxyDHCPD')
    @patch('proxydhcpd.cli.setup_global_logger')
    @patch('os.access', return_value=True)
    def test_daemon_umask(self, mock_access, mock_logger, mock_proxy, mock_dhcpd, mock_parse_args, mock_exit, mock_umask, mock_setsid, mock_chdir, mock_fork):
        class DummyArgs:
            config = "proxy.ini"
            daemon = True
            proxy_only = False
        mock_parse_args.return_value = DummyArgs()

        mock_fork.side_effect = [0, OSError(12, "Cannot allocate memory")]
        mock_exit.side_effect = SystemExit

        try:
            proxydhcpd.cli.main()
        except SystemExit:
            pass

        mock_umask.assert_called_with(0o022)

if __name__ == '__main__':
    unittest.main()
