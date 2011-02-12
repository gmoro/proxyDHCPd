#!/usr/bin/python
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

import time
import sys
import os
import getopt
import thread
import socket
import traceback

from dhcpd import DHCPD,ProxyDHCPD

def usage():
    print """
Usage %s [-c file] [-h] [-d] [-p]

Options:
    -c file  : Specify config file. Defaults is proxy.ini
    -d       : Run as daemon (ignored on Win32)
    -p       : Run only the ProxyDHCP Server
    -h       : Help - this screen 
    
    """ % sys.argv[0]

def main():
    if os.geteuid() != 0:
        print "You must be root to run the proxy"
        sys.exit(1)
        
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:dp")
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)
        
    # Set defaults, check options supplied
    configfile = 'proxy.ini'
    daemon = False
    proxy_only= False
    
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-c", "--config"):
            configfile = a
        elif o == "-d":      
            if sys.platform == 'win32':
                print "Ignoring request to run as daemon"
            else:
                daemon = True
        elif o == "-p":
            proxy_only=True
        else:
            assert False, "Unhandled option"
            
    if os.access(configfile, os.R_OK) == False:
        print "Unable to read config file: %s" % configfile
        usage()
        sys.exit(2)

    server=None

    # Set up a DHCPD instance
    if not proxy_only:
        try:
            server = DHCPD(configfile)
        except socket.error, msg:
            print "Error initiating on normal port, will try only 4011"
        except:
            traceback.print_exc()
            print("Failed to start.")
            sys.exit(1)
        
    try:
        proxyserver = ProxyDHCPD(configfile=configfile)
    except socket.error, msg:
        print "Error initiating Proxy, already running?"
        sys.exit(1)
    except:
        traceback.print_exc()
        print("Failed to start proxy.")
        sys.exit(1)
    
    # Daemonise
    if daemon == True:
        # Do double-fork magic
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            print("Fork #1 failed: %d (%s)" % ( e.errno, e.strerror))
            sys.exit(1)
            
        # Decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        
        # Do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent
                server.logger.info("proxy daemon has PID %d" % pid)
                server.logger.removeHandler(server.consoleLog)
                sys.exit(0)
        except OSError, e:
            print( "Fork #2 failed: %d (%s)" % ( e.errno, e.strerror) )
            sys.exit(1)

    # Start loop
    if server:
        server.logger.info('Listening on ' + server.config['proxy']['listen_address'])
        thread.start_new_thread(server.run,())
    thread.start_new_thread(proxyserver.run,())

    while proxyserver.loop and server.loop:
        try:
            time.sleep(1)
        except (KeyboardInterrupt,SystemExit):
            print "Exiting...."
            server.loop = False
            proxyserver.loop = False
            
if __name__ == "__main__":
    main()
