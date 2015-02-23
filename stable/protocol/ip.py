'''
    Class define IP protocol
'''
import socket
import struct
from common import checksum

class layer(object):
    pass

class IP(object):
    def __init__(self, src, dst, proto=socket.IPPROTO_TCP):
                self.version = 4
                self.ihl = 5 # Internet Header Length
                self.tos = 0 # Type of Service
                self.length = 40 # total length will be filled by kernel
                self.id = 54321
                self.flags = 0
                self.offset = 0
                self.ttl = 64
                self.protocol = proto
                self.checksum = 0 # will be filled by kernel
                self.src = socket.inet_aton(src)
                self.dst = socket.inet_aton(dst)
                self.ver_ihl = (self.version << 4) + self.ihl
                self.flags_offset = (self.flags << 13) + self.offset
    def pack(self):
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    self.ver_ihl,
                    self.tos,
                    self.length,
                    self.id,
                    self.flags_offset,
                    self.ttl,
                    self.protocol,
                    0, # checksum should be 0
                    self.src,
                    self.dst)
        self.checksum = checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    self.ver_ihl,
                    self.tos,
                    self.length,
                    self.id,
                    self.flags_offset,
                    self.ttl,
                    self.protocol,
                    socket.htons(self.checksum),
                    self.src,
                    self.dst)
        return ip_header
    def unpack(self, packet):
            _ip = layer()
            _ip.ihl = (ord(packet[0]) & 0xf) * 4
            iph = struct.unpack("!BBHHHBBH4s4s", packet[:_ip.ihl])
            _ip.ver = iph[0] >> 4
            _ip.tos = iph[1]
            _ip.length = iph[2]
            _ip.ids = iph[3]
            _ip.flags = iph[4] >> 13
            _ip.offset = iph[4] & 0x1FFF
            _ip.ttl = iph[5]
            _ip.protocol = iph[6]
            _ip.checksum = hex(iph[7])
            _ip.src = socket.inet_ntoa(iph[8])
            _ip.dst = socket.inet_ntoa(iph[9])
            _ip.list = [
                _ip.ihl,
                _ip.ver,
                _ip.tos,
                _ip.length,
                _ip.ids,
                _ip.flags,
                _ip.offset,
                _ip.ttl,
                _ip.protocol,
                _ip.src,
                _ip.dst]
            return _ip
