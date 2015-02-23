import struct
import socket
from common import checksum

class UDP(object):
    def __init__(self, src, dst, payload=''):
        self.srcp = src
        self.dstp = dst
        self.payload = payload
        self.checksum = 0
        self.length = 8 # UDP Header length
    def pack(self, src, dst, proto=socket.IPPROTO_UDP):
        length = self.length + len(self.payload)
        pseudo_header = struct.pack('!4s4sBBH', src, dst, 0, 
            proto, length)
        self.checksum = checksum(pseudo_header)
        packet = struct.pack('!HHHH',
            self.srcp, self.dstp, length, 0)
        return packet
