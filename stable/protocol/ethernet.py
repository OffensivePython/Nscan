'''
    Ethernet
'''

import struct

class layer():
    pass

class ETHER(object):
    def __init__(self, src='', dst='', type=''):
        self.src = src
        self.dst = dst
        self.type = type
    def pack(self):
        ethernet = struct.pack('!6s6sH',
                               self.dst,
                               self.src,
                               self.type)
        return ethernet
    def unpack(self, data):
        ethernet = layer()
        packet = data[:14]
        dst, src, type = struct.unpack('!6s6sH', packet)
        ethernet.src = src
        ethernet.dst = dst
        ethernet.type = type
        ethernet.list = [dst, src, type]
        return ethernet
