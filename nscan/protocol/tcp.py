import struct
from socket import htons, IPPROTO_TCP
from common import checksum

class layer(object):
    pass

class TCP(object):
    def __init__(self, srcp, dstp):
        self.srcp = srcp
        self.dstp = dstp
        self.seqn = 10
        self.ackn = 0
        self.offset = 5 # Data offset: 5x4 = 20 bytes
        self.reserved = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 1
        self.fin = 0
        self.window = htons(5840)
        self.checksum = 0
        self.urgp = 0
        self.payload = ""
    def pack(self, src, dst):
        data_offset = (self.offset << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        tcp_header = struct.pack('!HHLLBBHHH', 
                     self.srcp, 
                     self.dstp, 
                     self.seqn, 
                     self.ackn, 
                     data_offset, 
                     flags,  
                     self.window,
                     self.checksum,
                     self.urgp)
        #pseudo header fields
        #source_ip = src
        #destination_ip = dst
        reserved = 0
        protocol = IPPROTO_TCP
        total_length = len(tcp_header) + len(self.payload)
        # Pseudo header
        psh = struct.pack("!4s4sBBH",
              src,
              dst,
              reserved,
              protocol,
              total_length)
        psh = psh + tcp_header + self.payload
        tcp_checksum = checksum(psh)
        tcp_header = struct.pack("!HHLLBBH",
                  self.srcp,
                  self.dstp,
                  self.seqn,
                  self.ackn,
                  data_offset,
                  flags,
                  self.window)
        tcp_header+= struct.pack('H', tcp_checksum) + struct.pack('!H', self.urgp)
        return tcp_header
    def unpack(self, packet):
        cflags = { # Control flags
            32:"U",
            16:"A",
            8:"P",
            4:"R",
            2:"S",
            1:"F"}
        _tcp = layer()
        _tcp.thl = (ord(packet[12])>>4) * 4
        _tcp.options = packet[20:_tcp.thl]
        _tcp.payload = packet[_tcp.thl:]
        tcph = struct.unpack("!HHLLBBHHH", packet[:20])
        _tcp.srcp = tcph[0] # source port
        _tcp.dstp = tcph[1] # destination port
        _tcp.seq = tcph[2] # sequence number
        _tcp.ack = hex(tcph[3]) # acknowledgment number
        _tcp.flags = ""
        for f in cflags:
            if tcph[5] & f:
                _tcp.flags+=cflags[f]
        _tcp.window = tcph[6] # window
        _tcp.checksum = hex(tcph[7]) # checksum
        _tcp.urg = tcph[8] # urgent pointer
        _tcp.list = [
            _tcp.srcp,
            _tcp.dstp,
            _tcp.seq,
            _tcp.ack,
            _tcp.thl,
            _tcp.flags,
            _tcp.window,
            _tcp.checksum,
            _tcp.urg,
            _tcp.options,
            _tcp.payload]
        return _tcp 
