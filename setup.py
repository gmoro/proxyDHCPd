#!/usr/bin/env python
"""
Copyright Guilherme Moro 2011.

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

import sys, os
from distutils.core import setup

if os.name == 'nt':
    from py2exe.build_exe import py2exe

    setup(name='proxydhcpd',
          version='0.1',
          description = "proxy DHCP server",
          long_description="proxyDHCPd is a proxy DHCP implementation made in pure python and is fully \
                            compliant with the PXE specification. As a pure python project, it can run on \
                            Windows, Linux and MacOS (or any other platform that supports python)",
          url='http://github.com/gmoro/proxyDHCPd',
          author='Guilherme Moro',
          author_email='guilherme.moro@gmail.com',
          console=['proxydhpcd.py'],
    	  service=[{'modules': ['proxyservice'], 'cmdline_style': 'pywin32'}],
          options={"py2exe": {
                        "optimize": 2,
                        "bundle_files": 1
                        }
                   },
          data_files=[('',['proxy.ini'])],
          zipfile = None
          )
else:
      setup(name='proxydhcpd',
      version="0.1",
      license='GPL v2',
      description="proxy DHCP server",
      author='Guilherme Moro',
      author_email='guilherme.moro@gmail.com',
      url='http://github.com/gmoro/proxyDHCPd',
      packages=['proxydhcpd',"proxydhcpd.dhcplib"],
      scripts=['proxydhcpd.py'],
      data_files=[("/etc/proxyDHCPd",["proxy.ini"])]
       
      )