import pytest
from unittest.mock import MagicMock, call, patch
import sys
import os

# Ensure the parent directory is resolvable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxydhcpd.dhcpd import ProxyDHCPD

class TestProxyDHCPD:
    @pytest.fixture
    @patch('proxydhcpd.dhcpd.parse_config')
    @patch('proxydhcpd.dhcpd.socket.socket')
    def proxy_daemon(self, mock_socket, mock_parse_config):
        # Provide a safe mock configuration
        mock_parse_config.return_value = {
            'proxy': {
                'listen_address': '192.168.1.10',
                'tftpd': '192.168.1.10',
                'filename': 'undionly.kpxe',
                'vendor_specific_information': ''
            },
            'ipxe': {
                'enabled': 'True',
                'legacy_bootstrap': 'undionly.kpxe',
                'efi_bootstrap': 'ipxe.efi',
                'chainload_url': 'boot.ipxe'
            }
        }
        
        # Instantiate without actual network binding
        daemon = ProxyDHCPD(configfile='dummy.ini')
        # Mock the SendDhcpPacketTo to prevent actual UDP sends during test
        daemon.SendDhcpPacketTo = MagicMock()
        return daemon

    def _build_mock_packet(self, vendor_class="PXEClient", user_class=None, client_system=None):
        packet = MagicMock()
        options = {}
        
        # pydhcplib GetOption payload simulations (lists of ascii byte ints)
        if vendor_class:
            options['vendor_class_identifier'] = [ord(c) for c in vendor_class]
            
        if user_class:
            options['user_class'] = [ord(c) for c in user_class]
            
        if client_system is not None:
            # client_system representing Option 93 architectures (e.g. [0, 0])
            options['client_system'] = client_system
            
        # Optional defaults required by CreateDhcpAckPacketFrom
        options['hlen'] = 6
        options['htype'] = 1
        options['xid'] = [1, 2, 3, 4]
        options['flags'] = [0, 0]
        options['giaddr'] = [0, 0, 0, 0]
        options['ciaddr'] = [0, 0, 0, 0]
        
        packet.IsOption.side_effect = lambda x: x in options
        
        def mock_get_option(opt):
            return options.get(opt, [])
            
        packet.GetOption.side_effect = mock_get_option
        packet.GetHardwareAddress.return_value = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        
        return packet

    @patch('proxydhcpd.dhcpd.strlist')
    @patch('proxydhcpd.dhcpd.DhcpPacket')
    def test_ipxe_detected_chainload(self, mock_dhcp_packet_cls, mock_strlist, proxy_daemon):
        """Test Scenario A: Option 77 has 'iPXE'. Assert Option 67 is `chainload_url`"""
        mock_strlist_instance = MagicMock()
        mock_strlist_instance.str.return_value = "PXEClient"
        mock_strlist.return_value = mock_strlist_instance
        
        mock_response_packet = MagicMock()
        mock_dhcp_packet_cls.return_value = mock_response_packet
        
        # Create packet with 'iPXE' in Option 77
        incoming_packet = self._build_mock_packet(user_class="iPXE")
        
        proxy_daemon.HandleDhcpRequest(incoming_packet)
        
        mock_response_packet.SetOption.assert_any_call('file', b'boot.ipxe'.ljust(128, b'\0'))
        mock_response_packet.SetOption.assert_any_call('bootfile_name', b'boot.ipxe\0')

    @patch('proxydhcpd.dhcpd.strlist')
    @patch('proxydhcpd.dhcpd.DhcpPacket')
    def test_legacy_bios_bootstrap(self, mock_dhcp_packet_cls, mock_strlist, proxy_daemon):
        """Test Scenario B: Option 93 is `[0, 0]`. Assert Option 67 is `legacy_bootstrap`"""
        mock_strlist_instance = MagicMock()
        mock_strlist_instance.str.return_value = "PXEClient"
        mock_strlist.return_value = mock_strlist_instance
        
        mock_response_packet = MagicMock()
        mock_dhcp_packet_cls.return_value = mock_response_packet
        
        # Create packet with empty Option 77, Option 93 = [0, 0] (Legacy)
        incoming_packet = self._build_mock_packet(client_system=[0, 0])
        
        proxy_daemon.HandleDhcpRequest(incoming_packet)
        
        mock_response_packet.SetOption.assert_any_call('file', b'undionly.kpxe'.ljust(128, b'\0'))

    @patch('proxydhcpd.dhcpd.strlist')
    @patch('proxydhcpd.dhcpd.DhcpPacket')
    def test_uefi_x64_bootstrap(self, mock_dhcp_packet_cls, mock_strlist, proxy_daemon):
        """Test Scenario C: Option 93 is `[0, 9]`. Assert Option 67 is `efi_bootstrap`"""
        mock_strlist_instance = MagicMock()
        mock_strlist_instance.str.return_value = "PXEClient"
        mock_strlist.return_value = mock_strlist_instance
        
        mock_response_packet = MagicMock()
        mock_dhcp_packet_cls.return_value = mock_response_packet
        
        # Option 93 = [0, 9] (UEFI)
        incoming_packet = self._build_mock_packet(client_system=[0, 9])
        
        proxy_daemon.HandleDhcpRequest(incoming_packet)
        
        mock_response_packet.SetOption.assert_any_call('file', b'ipxe.efi'.ljust(128, b'\0'))

    @patch('proxydhcpd.dhcpd.strlist')
    @patch('proxydhcpd.dhcpd.DhcpPacket')
    def test_unsupported_architecture_drop(self, mock_dhcp_packet_cls, mock_strlist, proxy_daemon):
        """Test Scenario D: Option 93 is `[0, 11]`. Assert payload drops (Option 67 not set)"""
        mock_strlist_instance = MagicMock()
        mock_strlist_instance.str.return_value = "PXEClient"
        mock_strlist.return_value = mock_strlist_instance
        
        mock_response_packet = MagicMock()
        mock_dhcp_packet_cls.return_value = mock_response_packet
        
        # Option 93 = [0, 11] (ARM64, unsupported natively by config)
        incoming_packet = self._build_mock_packet(client_system=[0, 11])
        
        proxy_daemon.HandleDhcpRequest(incoming_packet)
        
        # Assert file was NOT set
        for call_args in mock_response_packet.SetOption.call_args_list:
            assert call_args[0][0] not in ['file', 'bootfile_name'], "Option 67 should not be set for unsupported architectures"

    @patch('proxydhcpd.dhcpd.strlist')
    @patch('proxydhcpd.dhcpd.DhcpPacket')
    def test_ipxe_disabled_fallback(self, mock_dhcp_packet_cls, mock_strlist, proxy_daemon):
        """Test Scenario E: Config `enabled=False`. Assert standard legacy fallback occurs"""
        # Override config dynamically
        proxy_daemon.config['ipxe']['enabled'] = 'False'
        
        mock_strlist_instance = MagicMock()
        mock_strlist_instance.str.return_value = "PXEClient"
        mock_strlist.return_value = mock_strlist_instance
        
        mock_response_packet = MagicMock()
        mock_dhcp_packet_cls.return_value = mock_response_packet
        
        # iPXE client but iPXE routing is disabled
        incoming_packet = self._build_mock_packet(user_class="iPXE")
        
        # Mock the legacy fallback function get_boot_filename entirely
        proxy_daemon.get_boot_filename = MagicMock(return_value='fallback.kpxe')
        
        proxy_daemon.HandleDhcpRequest(incoming_packet)
        
        # Assert legacy fallback file was encoded
        mock_response_packet.SetOption.assert_any_call('file', b'fallback.kpxe'.ljust(128, b'\0'))
