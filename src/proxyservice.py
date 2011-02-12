"""
Copyright Andrew Tunnell-Jones 2008.

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

import getopt
import servicemanager
import winerror
import win32serviceutil
import win32service
import win32traceutil
import win32event
import time
import sys
import os
import thread
import socket
import traceback
from dhcpd import DHCPD,ProxyDHCPD

class proxyService(win32serviceutil.ServiceFramework):
    __version__ = "0.1"
    _svc_name_ = "bootproxy"
    _svc_display_name_ = "Boot Proxy Server"
    debug = False
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        import servicemanager
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE, 
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ''))
        configfile = win32serviceutil.GetServiceCustomOption(proxyService._svc_name_,'config')
        if configfile == None or configfile == "":
            self_path = os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
            configfile = self_path + '\\proxy.ini'
        try:
            class winDHCPD(DHCPD):
                def log(self,level,message):
                    if level == 'info':
                        servicemanager.LogInfoMsg(message)
                        self.logger.info(message)
                    else:
                        self.logger.debug(message)
            server = winDHCPD(configfile)
        except:
            print "Failed to start."
            sys.exit(1)
        # Start Proxy at port 4011    
        try:
            class winProxyDHCPD(ProxyDHCPD):
                def log(self,level,message):
                    if level == 'info':
                        servicemanager.LogInfoMsg(message)
                        self.logger.info(message)
                    else:
                        self.logger.debug(message)
            proxyserver = winProxyDHCPD(configfile)
        except socket.error, msg:
            print "Error initiating Proxy, already running?"
        except:
            traceback.print_exc()
            print("Failed to start proxy.")
            sys.exit(1)
            
        if self.debug == False:
            thread.start_new_thread(proxyserver.run,())
            thread.start_new_thread(server.run,())
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            server.loop = False
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE, 
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ''))
            sys.exit(0)
        else:
            thread.start_new_thread(server.run,())
            thread.start_new_thread(proxyserver.run,())
            print "Will exit in 30 seconds"
            try:
                time.sleep(30)
            except (KeyboardInterrupt,SystemExit):
                server.loop = False
            server.loop = False 
            sys.exit(0)
            
if __name__=='__main__':# or hasattr(sys, 'frozen'):
    win32serviceutil.HandleCommandLine(proxyService)
