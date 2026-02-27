import socket
import fcntl
import struct
import array

def get_ip_address(ifname):
    if isinstance(ifname, str):
        ifname = ifname.encode('utf-8')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except OSError:
        return None

def all_interfaces():
    return [i[1] for i in socket.if_nameindex()]

def get_dev_name(ipaddr):
    for netdev in all_interfaces():
        if get_ip_address(netdev) == ipaddr:
            return netdev