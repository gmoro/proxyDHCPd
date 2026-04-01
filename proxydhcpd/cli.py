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

from .dhcpd import DHCPD, ProxyDHCPD
from . import __version__
import argparse
import os
import socket
import sys
import threading
import time
import traceback

import logging
import logging.handlers


def setup_global_logger():
    logger = logging.getLogger('proxydhcp')
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s %(levelname)s ProxyDHCP: %(message)s')  
        consoleLog = logging.StreamHandler()
        consoleLog.setFormatter(formatter)
        logger.addHandler(consoleLog)
        
        if sys.platform == 'win32':
            fileLog = logging.FileHandler('proxy.log')
            fileLog.setFormatter(formatter)
            logger.addHandler(fileLog)
        else:
            if sys.platform == 'darwin':
                syslogLog = logging.handlers.SysLogHandler("/var/run/syslog")
            else:
                syslogLog = logging.handlers.SysLogHandler("/dev/log")
            syslogLog.setFormatter(formatter)
            syslogLog.setLevel(logging.INFO)
            logger.addHandler(syslogLog)


def main():
    parser = argparse.ArgumentParser(
        prog='proxydhcpd',
        description='ProxyDHCPd — A proxy DHCP server in pure Python 3 with native iPXE chainloading.',
    )
    parser.add_argument(
        '-V', '--version',
        action='version',
        version='%(prog)s ' + __version__,
    )
    parser.add_argument(
        '-c', '--config',
        default='/etc/proxydhcpd/proxy.ini',
        metavar='FILE',
        help='Path to the configuration file (default: /etc/proxydhcpd/proxy.ini)',
    )
    parser.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run as a background daemon via double-fork (ignored on Win32)',
    )
    parser.add_argument(
        '-p', '--proxy-only',
        action='store_true',
        help='Run only the ProxyDHCP server on port 4011 (skip port 67)',
    )

    args = parser.parse_args()

    setup_global_logger()

    configfile = args.config
    daemon = args.daemon
    proxy_only = args.proxy_only

    if not os.access(configfile, os.R_OK):
        print("Unable to read config file: %s" % configfile)
        sys.exit(2)

    server = None

    # Set up a DHCPD instance
    if not proxy_only:
        try:
            server = DHCPD(configfile)
        except socket.error as msg:
            print("Error initiating on normal port, will try only 4011")
        except Exception:
            traceback.print_exc()
            print("Failed to start.")
            sys.exit(1)
        
    try:
        proxyserver = ProxyDHCPD(configfile=configfile)
    except socket.error as msg:
        print("Error initiating Proxy, already running?")
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        print("Failed to start proxy.")
        sys.exit(1)
    
    # Daemonise
    if daemon:
        if sys.platform == 'win32':
            print("Ignoring request to run as daemon on Win32")
        else:
            # Do double-fork magic
            try:
                pid = os.fork()
                if pid > 0:
                    sys.exit(0)
            except OSError as e:
                print("Fork #1 failed: %d (%s)" % (e.errno, e.strerror))
                sys.exit(1)
                
            # Decouple from parent environment
            os.chdir("/")
            os.setsid()

            # Set a secure umask to ensure files created by the daemon
            # are not world-writable by default.
            os.umask(0o022)
            
            # Do second fork
            try:
                pid = os.fork()
                if pid > 0:
                    # Exit from second parent
                    if server:
                        server.logger.info("proxy daemon has PID %d" % pid)
                        server.logger.removeHandler(server.consoleLog)
                    sys.exit(0)
            except OSError as e:
                print("Fork #2 failed: %d (%s)" % (e.errno, e.strerror))
                sys.exit(1)

    # Start loop
    if server and proxyserver:
        server.logger.info('Listening on ' + server.config['proxy']['listen_address'])
        t1 = threading.Thread(target=server.run)
        t1.daemon = True
        t1.start()
    
    t2 = threading.Thread(target=proxyserver.run)
    t2.daemon = True
    t2.start()

    while (proxyserver and proxyserver.loop) or (server and server.loop):
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print("\nExiting....")
            if proxyserver:
                proxyserver.loop = False
            if server:
                server.loop = False
            
if __name__ == "__main__":
    main()
