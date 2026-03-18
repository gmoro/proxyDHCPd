"""

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
"""

from .proxyconfig import parse_config
from .dhcplib.dhcp_network import *
from .dhcplib.dhcp_packet import *
import logging
import logging.handlers
import sys
from . import net
import traceback

class DhcpServerBase(DhcpNetwork) :
    def __init__(self, listen_address="0.0.0.0", client_listen_port=68,server_listen_port=67, interface="") :
        
        DhcpNetwork.__init__(self,listen_address,server_listen_port,client_listen_port)
        
        self.logger = logging.getLogger('proxydhcp')
        
        try :
            #self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # --- PORT SHARING HACK ---
            # Allow binding to the same port as another process (e.g. dnsmasq)
            # dnsmasq would have to have this option set as well
            # otherwise we would need to use macvtap
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            # ------------------------------------
            
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            if sys.platform == 'win32':
                self.dhcp_socket.bind((self.listen_address,self.listen_port))
            else:
                ifname = interface
                if ifname:
                    SO_BINDTODEVICE = getattr(socket, 'SO_BINDTODEVICE', 25)
                    self.dhcp_socket.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (ifname+'\0').encode('utf-8'))
                
                self.dhcp_socket.bind(('',self.listen_port))
        
        except socket.error as msg :
            self.logger.critical("FATAL: Error creating socket or binding to interface %s on port %s: %s" % (self.listen_address, self.listen_port, str(msg)))
            sys.exit(1)
        except Exception as e:
            self.logger.critical("FATAL: Unexpected error initializing DHCP socket: %s" % str(e))
            sys.exit(1)
        
        self.loop = True
        
    def run(self):
        while self.loop:
            try:
                self.GetNextDhcpPacket()
            except Exception:
                traceback.print_exc()
        self.log('info','Service shutdown')
    
    def log(self,level,message):
        if level == 'info':
            self.logger.info(message)
        else:
            self.logger.debug(message)
            
class DHCPD(DhcpServerBase):
    loop = True
    def __init__(self,configfile='proxy.ini',client_port=68,server_port=67):
        
        self.client_port = int(client_port)
        self.server_port = int(server_port)
        self.config = parse_config(configfile)
        DhcpServerBase.__init__(self, self.config['proxy'].get("listen_address", "0.0.0.0"), self.client_port, self.server_port, self.config['proxy'].get("interface", ""))
        self.log('info',"Starting DHCP on ports client: %s, server: %s"%(self.client_port,self.server_port))

    def HandleDhcpDiscover(self, packet):
        if packet.IsOption('vendor_class_identifier'):
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            if class_identifier.str()[0:9] == "PXEClient":
                responsepacket = DhcpPacket()
                responsepacket.CreateDhcpOfferPacketFrom(packet)
                responsepacket.SetMultipleOptions( {
                    'hlen': packet.GetOption("hlen"),
                    'htype': packet.GetOption("htype"),
                    'xid': packet.GetOption("xid"),
                    'flags': packet.GetOption("flags"),
                    'giaddr': packet.GetOption("giaddr"),
                    'yiaddr':[0,0,0,0],
                    'ciaddr':[0,0,0,0]
                    } )
                responsepacket.SetOption("vendor_class_identifier", b"PXEClient")
                responsepacket.SetOption("server_identifier", list(map(int, self.config['proxy']["listen_address"].split("."))))
                if self.config['proxy']['vendor_specific_information']:
                    responsepacket.SetOption('vendor_specific_information', self.config['proxy']['vendor_specific_information'].encode('ascii'))
                    
                responsepacket.DeleteOption('ip_address_lease_time')
                self.SendDhcpPacketTo(responsepacket, "255.255.255.255", self.client_port)
                self.log('info','******Responded to PXE Discover from ' + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))
            else:
                self.log('debug','Noticed a non-boot DHCP Discover packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))
        else:
            self.log('debug','Noticed a non-boot DHCP Discover packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpRequest(self, packet):
        self.log('debug','Noticed a DHCP Request (port 67) packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def fmtHex(self,input):
        return f"{input:02x}"

class ProxyDHCPD(DHCPD):
    
    def __init__(self,configfile='proxy.ini',client_port=68,server_port=4011):
        self.config = parse_config(configfile)
        self.client_port = client_port
        self.server_port = server_port
        DHCPD.__init__(self,configfile,server_port=server_port)

    def get_boot_filename(self, packet):
        default_file = self.config['proxy']['filename']
        if not packet.IsOption('client_system'):
            return default_file
            
        arch_opt = packet.GetOption('client_system')
        if not arch_opt:
            return default_file
            
        # Option 93 is unassigned natively so it comes back as a list of integers
        arch_list = arch_opt
        if hasattr(arch_opt, 'list'):
            arch_list = arch_opt.list()
            
        if len(arch_list) >= 2:
            arch = arch_list[1]
            if arch == 6:
                return self.config['proxy'].get('filename_efi32', default_file)
            elif arch in [7, 9]:
                return self.config['proxy'].get('filename_efi64', default_file)
                
        return default_file

    def HandleDhcpDiscover(self, packet):
        self.log('debug','Noticed a DHCP Discover packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))
    
    def HandleDhcpRequest(self, packet):
        if packet.IsOption('vendor_class_identifier'):
            
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            if class_identifier.str()[0:9] == "PXEClient":
                
                # 1. CONFIGURATION PARSING WITH FALLBACKS
                ipxe_cfg = self.config.get('ipxe', {})
                ipxe_enabled = str(ipxe_cfg.get('enabled', 'False')).lower() == 'true'
                legacy_bootstrap = ipxe_cfg.get('legacy_bootstrap', 'undionly.kpxe')
                efi_bootstrap = ipxe_cfg.get('efi_bootstrap', 'ipxe.efi')
                chainload_url = ipxe_cfg.get('chainload_url', 'boot.ipxe')

                # 2. THE ROUTING LOGIC (Option 77 and Option 93)
                user_class = packet.GetOption('user_class') if packet.IsOption('user_class') else []
                client_arch = packet.GetOption('client_system') if packet.IsOption('client_system') else []

                # Convert Option 77 to a string safely
                user_class_str = ""
                if user_class:
                    user_class_list = user_class.list() if hasattr(user_class, 'list') else user_class
                    user_class_str = "".join([chr(c) for c in user_class_list if c != 0])

                # Extract Option 93 architecture list
                arch_list = []
                if client_arch:
                    arch_list = client_arch.list() if hasattr(client_arch, 'list') else client_arch

                # Determine the target boot file
                boot_file_name = None
                if ipxe_enabled:
                    if 'iPXE' in user_class_str:
                        boot_file_name = chainload_url
                        self.log('info', 'iPXE client detected. Directing to chainload URL: %s' % chainload_url)
                    elif arch_list == [0, 0]:
                        boot_file_name = legacy_bootstrap
                        self.log('info', 'Legacy BIOS hardware detected. Directing to %s' % legacy_bootstrap)
                    elif arch_list == [0, 7] or arch_list == [0, 9]:
                        boot_file_name = efi_bootstrap
                        self.log('info', 'UEFI hardware detected. Directing to %s' % efi_bootstrap)
                    else:
                        self.log('warning', 'Unsupported architecture detected: %s. Dropping payload.' % str(arch_list))
                        boot_file_name = None
                else:
                    # Fallback to standard ProxyDHCP legacy handling
                    boot_file_name = self.get_boot_filename(packet)
                
                responsepacket = DhcpPacket()
                responsepacket.CreateDhcpAckPacketFrom(packet)
                responsepacket.SetMultipleOptions( {
                    'hlen': packet.GetOption("hlen"),
                    'htype': packet.GetOption("htype"),
                    'xid': packet.GetOption("xid"),
                    'flags': packet.GetOption("flags"),
                    'giaddr': packet.GetOption("giaddr"),
                    'yiaddr':[0,0,0,0],
                    'siaddr': self.config['proxy']['tftpd'],
                    'vendor_class_identifier': b"PXEClient",
                    'server_identifier': list(map(int, self.config['proxy']["listen_address"].split("."))),
                    'tftp_server_name': self.config['proxy']['tftpd']
                } )
                
                # 3. EDGE CASE HANDLING (EMPTY OR NONE VALUES)
                if boot_file_name:
                    file_payload = boot_file_name.ljust(128, "\0").encode('ascii')
                    bootfile_name_payload = (boot_file_name + "\0").encode('ascii')
                    responsepacket.SetOption('file', file_payload)
                    responsepacket.SetOption('bootfile_name', bootfile_name_payload)
                else:
                    self.log('debug', 'boot_file_name is empty, skipping Option 67 (bootfile_name)')
                
                if self.config['proxy'].get('vendor_specific_information'):
                    responsepacket.SetOption('vendor_specific_information', self.config['proxy']['vendor_specific_information'].encode('ascii'))
                    
                responsepacket.DeleteOption('ip_address_lease_time')
                self.SendDhcpPacketTo(responsepacket, ".".join(list(map(str,packet.GetOption('ciaddr')))), self.client_port)
                self.log('info','****Responded to PXE request (port 4011) from ' + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(list(map(self.fmtHex,packet.GetHardwareAddress()))))

    def fmtHex(self,input):
        return f"{input:02x}"