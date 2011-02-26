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

from proxyconfig import parse_config
from dhcplib.dhcp_network import *
from dhcplib.dhcp_packet import *
import logging
import logging.handlers
import sys
import net
import traceback

#this class was necessary for get the exceptions the right way
class MyDhcpServer(DhcpNetwork) :
    def __init__(self, listen_address="0.0.0.0", client_listen_port=68,server_listen_port=67) :
        
        DhcpNetwork.__init__(self,listen_address,server_listen_port,client_listen_port)
        
        self.logger = logging.getLogger('proxydhcp')
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s ProxyDHCP: %(message)s')  
        self.consoleLog = logging.StreamHandler()
        self.consoleLog.setFormatter(formatter)
        self.logger.addHandler(self.consoleLog)
        if sys.platform == 'win32':
            self.fileLog = logging.FileHandler('proxy.log')
            self.fileLog.setFormatter(formatter)
            self.logger.addHandler(self.fileLog)
        else:
            if sys.platform == 'darwin':
                self.syslogLog = logging.handlers.SysLogHandler("/var/run/syslog")
            else:
                self.syslogLog = logging.handlers.SysLogHandler("/dev/log")
            self.syslogLog.setFormatter(formatter)
            self.syslogLog.setLevel(logging.INFO)
            self.logger.addHandler(self.syslogLog)
        
        try :
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            if sys.platform == 'win32':
                self.dhcp_socket.bind((self.listen_address,self.listen_port))
            else:
                # Linux and windows differ on the way they bind to broadcast sockets
                ifname = net.get_dev_name(self.listen_address)
                self.dhcp_socket.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE,ifname+'\0')
                self.dhcp_socket.bind(('',self.listen_port))
        except socket.error, msg :
            self.log('info',"Error creating socket for server: \n %s"%str(msg))
        
        self.loop = True
        
    def run(self):
        while self.loop:
            try:
                self.GetNextDhcpPacket()
            except:
                traceback.print_exc()
        self.log('info','Service shutdown')
    
    def log(self,level,message):
        if level == 'info':
            self.logger.info(message)
        else:
            self.logger.debug(message)
            
class DHCPD(MyDhcpServer):
    loop = True
    def __init__(self,configfile='proxy.ini',client_port=68,server_port=67):
        
        self.client_port = int(client_port)
        self.server_port = int(server_port)
        self.config = parse_config(configfile)
        MyDhcpServer.__init__(self,self.config['proxy']["listen_address"],self.client_port,self.server_port)
        self.log('info',"Starting DHCP on ports client: %s, server: %s"%(self.client_port,self.server_port))

    def HandleDhcpDiscover(self, packet):
        #print packet.str()
        if packet.IsOption('vendor_class_identifier'):
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            print class_identifier
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
                responsepacket.SetOption("vendor_class_identifier", map(ord, "PXEClient"))
                responsepacket.SetOption("server_identifier",map(int, self.config['proxy']["listen_address"].split(".")))
                if self.config['proxy']['vendor_specific_information']:
                    responsepacket.SetOption('vendor_specific_information', map(ord, self.config['proxy']['vendor_specific_information']))
                    
                responsepacket.DeleteOption('ip_address_lease_time')
                self.SendDhcpPacketTo(responsepacket, "255.255.255.255", self.client_port)
                self.log('info','******Responded to PXE Discover from ' + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
            else:
                self.log('debug','Noticed a non-boot DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
        else:
            self.log('debug','Noticed a non-boot DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRequest(self, packet):
        self.log('debug','Noticed a DHCP Request (port 67) packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def fmtHex(self,input):
        input=hex(input)
        input=str(input)
        input=input.replace("0x","")
        if len(input)==1:
            input="0"+input
        return input

class ProxyDHCPD(DHCPD):
    
    def __init__(self,configfile='proxy.ini',client_port=68,server_port=4011):
        self.config = parse_config(configfile)
        self.client_port = client_port
        self.server_port = server_port
        DHCPD.__init__(self,configfile,server_port=server_port)

    def HandleDhcpDiscover(self, packet):
        self.log('debug','Noticed a DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
    
    def HandleDhcpRequest(self, packet):
        if packet.IsOption('vendor_class_identifier'):
            
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            if class_identifier.str()[0:9] == "PXEClient":
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
                    'file': map(ord, (self.config['proxy']['filename'].ljust(128,"\0"))),
                    'vendor_class_identifier': map(ord, "PXEClient"),
                    'server_identifier': map(int, self.config['proxy']["listen_address"].split(".")), # This is incorrect but apparently makes certain Intel cards happy
                    'bootfile_name': map(ord, self.config['proxy']['filename'] + "\0"),
                    'tftp_server_name': self.config['proxy']['tftpd']
                } )
                
                if self.config['vendor_specific_information']:
                    responsepacket.setOption('vendor_specific_information', map(ord, self.config['vendor_specific_information']))
                    
                responsepacket.DeleteOption('ip_address_lease_time')
                self.SendDhcpPacketTo(responsepacket, ".".join(map(str,packet.GetOption('ciaddr'))), self.client_port)
                self.log('info','****Responded to PXE request (port 4011 ) from ' + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    #===========================================================================
    # def run(self):
    #    while self.loop:
    #        self.GetNextDhcpPacket()
    #    self.log('info','Service shutdown')
    #===========================================================================

    def fmtHex(self,input):
        input=hex(input)
        input=str(input)
        input=input.replace("0x","")
        if len(input)==1:
            input="0"+input
        return input