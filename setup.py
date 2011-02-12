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

import sys, os
from distutils.core import setup
from py2exe.build_exe import py2exe

import psyco
psyco.full()

if os.name == 'nt':
    setup(name='proxydhcp',
          version='0.1',
          description = "",
          long_description="",
          url='http://none',
          author='Guilherme Moro',
          author_email='guilherme.moro@gmail.com',
          console=['proxydhp.py'],
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
    print "I'll get to ya...."