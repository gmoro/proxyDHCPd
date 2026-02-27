# pydhcplib
# Copyright (C) 2008 Mathieu Ignacio -- mignacio@april.org
#
# This file is part of pydhcplib.
# Pydhcplib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

class strlist :
    def __init__(self,data="") :
        str_type = type(data)
        self._str = ""
        self._list = []
        
        if str_type == str :
            self._str = data
            for each in range(len(self._str)) :
                self._list.append(ord(self._str[each]))
        elif str_type == bytes :
            self._str = data.decode("utf-8", "ignore")
            for each in range(len(data)) :
                self._list.append(data[each])
        elif str_type == list :
            self._list = data
            self._str = "".join(map(chr,self._list))
        else : raise TypeError('strlist init : Valid types are str, bytes, and list of int')

    # return string
    def str(self) :
        return self._str

    # return list (useful for DhcpPacket class)
    def list(self) :
        return self._list

    # return int
    # FIXME
    def int(self) :
        return 0



    """ Useful function for native python operations """

    def __hash__(self) :
        return self._str.__hash__()

    def __repr__(self) :
        return self._str

    def __bool__(self) :
        if self._str != "" : return True
        return False

    def __eq__(self,other) :
        return self._str == other
		    


