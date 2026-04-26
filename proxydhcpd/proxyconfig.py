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

import os
import sys
import re
import configparser as ConfigParser

class parse_config(dict):
    cp = ConfigParser.ConfigParser()
    def __init__(self,configfile='proxy.ini'):
        if os.access(configfile, os.R_OK) == False:
            print("Unable to read config file: %s" % configfile)
            sys.exit(2)
        try:
            self.cp.read(configfile)
        except ConfigParser.Error:
            print('Unable to parse config file: %s' % configfile)
            sys.exit(2)
        for section in self.cp.sections():
            if section in ['proxy', 'pxe', 'ipxe']:
                self[section]={}
                for item in self.cp.items(section):
                    value = self.cp.get(section,item[0])
                    valuecheckmsg = 'Please check the value set for ' + item[0] + ' in the ' + section + ' section of ' + configfile
                    if item[0] == 'listen_address':
                        if self.listenAddressCheck(value):
                            self[section][item[0]] = value
                        else:
                            print(valuecheckmsg)
                            sys.exit(2)
                    elif item[0] == 'tftpd':
                        if self.ipAddressCheck(value):
                            self[section][item[0]] = list(map(int, value.split(".")))
                        else:
                            print(valuecheckmsg)
                            sys.exit(2)
                    elif item[0] in ['filename', 'filename_efi32', 'filename_efi64', 'interface', 'legacy_bootstrap', 'efi_bootstrap', 'chainload_url']:
                        if self.stringCheck(value):
                            self[section][item[0]] = value
                        else:
                            print(valuecheckmsg)
                            sys.exit(2)
                    elif item[0] in ['enabled']:
                        self[section][item[0]] = value
                    elif item[0] in ['vendor_specific_information']:
                        if self.stringCheck(value):
                            self[section][item[0]] = value
                        else:
                            print(valuecheckmsg)
                            sys.exit(2)
                    else:
                            print('The item ' + item[0] + ' in the ' + section + ' section of ' + configfile + ' is unknown')
                            sys.exit(2)
            else:
                print('The ' + section + ' section in ' + configfile + ' is unknown')
                exit(2)
            self['proxy']['client_listen_port'] = "68"
            self['proxy']['server_listen_port'] = "67"
            
        # Single Source of Truth / Converge config IPs
        from . import net
        conf_ip = self['proxy'].get("listen_address")
        conf_iface = self['proxy'].get("interface")
        
        if conf_iface and conf_ip:
            if_ip = net.get_ip_address(conf_iface)
            if if_ip != conf_ip:
                print("CRITICAL: Split-Brain Config! listen_address (%s) does not match IP of interface %s (%s)." % (conf_ip, conf_iface, if_ip))
                sys.exit(1)
        elif conf_iface:
            if_ip = net.get_ip_address(conf_iface)
            if not if_ip:
                print("CRITICAL: Cannot resolve IP for interface %s" % conf_iface)
                sys.exit(1)
            self['proxy']["listen_address"] = if_ip
        elif conf_ip:
            if_name = net.get_dev_name(conf_ip)
            if not if_name and conf_ip != "0.0.0.0":
                print("CRITICAL: Cannot resolve interface for IP %s" % conf_ip)
                sys.exit(1)
            self['proxy']["interface"] = if_name
        else:
            print("CRITICAL: You must provide either 'interface' or 'listen_address' in proxy.ini.")
            sys.exit(1)
                
    def ipAddressCheck(self,ip_str):
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        # 🛡️ Sentinel: Use re.fullmatch instead of re.match to prevent partial matches
        # that could allow malicious input with trailing garbage (e.g. "192.168.1.1; rm -rf /")
        if re.fullmatch(pattern, ip_str):
            return True
        else:
            return False
    
    def listenAddressCheck(self,ip_str):
        if (self.ipAddressCheck(ip_str) or "0.0.0.0" == ip_str):
            return True
        else:
            return False
    
    def intCheck(self,input):
        try:
            int(input)
        except ValueError:
            return False
        return True
    
    def stringCheck(self,input):
        if (type(input) == str and len(input) > 0):
            return True
        else:
            return False
            
if __name__ == "__main__":
    configp=parse_config()
    print(configp)
