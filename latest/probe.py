import time
import Queue
import random
import socket
import struct
import logging
import threading
from convert import *
from protocol import ethernet, ip, tcp, udp

ETH_P_IP = 0x0800 # IP protocol
ETH_P_ALL = 0x0003 # Every packet
NSCRIPT_PATH = 'nscript'  # NSCRIPT PATH

PAYLOAD = {
	53:('\x5d\x0d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06'
		'google\x03com\x00\x00\x01\x00\x01'), # 'google.com' DNS Lookup
	161:('\x30\x26\x02\x01\x01\x04\x06public\xa1\x19\x02'
		'\x04\x56\x9f\x5a\xdd\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06'
		'\x05\x2b\x06\x01\x02\x01\x05\x00'), # SNMP GetNextRequest|public|2c version|1.3.6.1.2.1
	123:('\x17\x00\x02\x05'), # NTP systats commands lacks 38 null bytes (just to save bandwidth)
	1900:('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

class Generator(object):
    def __init__(self, size):
        self.size = size
        self.inc = size/4
        if self.inc<1:
            self.inc = 1
        self.base = -self.inc
        self.num = self.base
        self.index = 0
    def __iter__(self):
        return self
    def next(self):
        if (self.num+self.inc)>=self.size:
            self.next_index()
            self.next_base()
        self.num = self.num + self.inc
        return self.num
    def next_base(self):
        self.base = 0
        self.base-= self.index
        self.num = self.base
    def next_index(self):
		self.index+=1
		if self.index>=self.inc:
			raise StopIteration
    def suspend(self):
        return self.size, self.inc, self.base, self.num, self.index
    def resume(self, size, inc, base, num, index):
        self.size = size
        self.inc = inc
        self.base = base
        self.num = num
        self.index = index

class ScriptEngine(object):
	def __init__(self, imports):
		self.imports = imports
		self.event = threading.Event()
		self.queues = {}
		self.thread = []
	def Load(self):
		for script in self.imports:
			q = Queue.Queue()
			s = __import__('{}.{}'.format(NSCRIPT_PATH, script),
				fromlist=[NSCRIPT_PATH])
			t = threading.Thread(target=s.run,
				args=(q, self.event))
			self.thread.append(t)
			t.setDaemon(True)
			t.start()
			self.queues[script] = q
	def Feed(self, host, port):
		for scr in self.imports:
			for r in self.imports[scr]:
				if port in xrange(r[0], r[1]):
					self.queues[scr].put((host, port))
					break
	def Cleanup(self):
		while Alive(self.thread):
			time.sleep(10)

class nscan(object):
	def __init__(self, options):
		self.options = options
		self.hosts = self.split(options.hosts, options.threads)
		self.ports = options.ports
		self.srcp = random.randint(1, 65535)#self.PickPort() # source port
		self.smac = options.smac
		self.dmac = options.dmac
		self.ifname = options.ifname
		self.siface = options.siface
		self.diface = options.diface
		self.banner = options.banner
		self.count = options.count
		self.cooldown = options.cooldown
		self.queue = Queue.Queue()
		if options.stype.upper()=='U':
			self.stype = socket.IPPROTO_UDP
		else:
			self.stype = socket.IPPROTO_TCP
		self.events = {
			'send': threading.Event(),
			'recv': threading.Event()}
		self.threads = {
			'send': [],
			'recv': None}
	def __Transport(self, src, dst=0):
		if self.stype==socket.IPPROTO_TCP:
			transport = tcp.TCP(src, dst)
			transport.seqn = 0xDEADC0DE
		else:
			transport = udp.UDP(src, dst)
		return transport
	def __Pack(self, transport, src, dst):
		if self.stype==socket.IPPROTO_TCP:
			transport.payload = ''
		else:
			transport.payload = PAYLOAD.get(transport.dstp, '\x00\r\n\r\n')
		packed = transport.pack(src, dst)
		return packed + transport.payload
	def __CookieCheck(self, data):
		check = False
		dstp = struct.unpack('!H', data[22:24])[0]
		if self.stype==socket.IPPROTO_UDP:
			if dstp==self.srcp:
				check = True
		else:
			ackn = struct.unpack('!L', data[28:32])[0]
			flags = struct.unpack('B', data[33])[0] & 0b010010 # SYN-ACK
			if dstp==self.srcp and ackn==0xDEADC0DF and flags==18:
				check = True
		return check
	def init(self):
		generators = []
		for h in self.hosts:
			g = Generator(h[1]-h[0])
			generators.append(g)
			t = threading.Thread(target=self.send, args=(h, self.srcp, g))
			t.setDaemon(True)
			self.threads['send'].append(t)
		t = threading.Thread(target=self.recv)
		t.setDaemon(True)
		self.threads['recv'] = t
		if 'resume' in dir(self.options):
			i = 0
			for g in generators:
				g.resume(*self.options.indexes[i])
				i+=1
		return self.threads, self.events, self.queue, generators
	def run(self):
		self.events['send'].set()
		self.events['recv'].set()
		for t in self.threads['send']:
			t.start()
		self.threads['recv'].start()
	def send(self, hosts, srcp, gen):
		if 'ppp' in self.ifname:
			family = socket.AF_INET
			proto = socket.IPPROTO_RAW
			eth = ''
		else:
			family = socket.AF_PACKET
			proto = ETH_P_IP
			eth = ethernet.ETHER(mac2byte(self.smac), mac2byte(self.dmac), ETH_P_IP).pack()
		sock = socket.socket(family, socket.SOCK_RAW, proto)
		transport = self.__Transport(srcp, 0)
		npacket = 0
		self.events['send'].wait()
		target = hosts[0]
		while self.events['send'].isSet():
			try:
				target = hosts[0] + gen.next()
				iph = ip.IP(self.diface, dec2dot(target), self.stype)
			except StopIteration:
				break
			for port_list in self.ports:
				for port in range(port_list[0], port_list[1]):
					if self.events['send'].isSet():
						transport.dstp = port
						packet = eth + iph.pack() + self.__Pack(transport, iph.src, iph.dst) #tcph.pack(iph.src, iph.dst)
						sock.sendto(packet, (dec2dot(target), 0)) # self.ifname
						npacket+=1
						if not npacket%self.cooldown[0]:
							time.sleep(self.cooldown[1])
					else:
						break
		logging.info('[SEND] Sent: {} packets'.format(npacket))
		sock.close()
	def recv(self):
		sock = socket.socket(socket.AF_INET,
			socket.SOCK_RAW,
			self.stype)
		sock.bind(('', self.srcp))
		sock.settimeout(5)
		self.events['recv'].wait()
		counter = 0
		while self.events['recv'].isSet():
			try:
				data, sa_ll = sock.recvfrom(65535)
				if self.__CookieCheck(data):
					self.queue.put(Extract(data))
					counter += 1
					if counter==self.count:
						self.events['send'].clear()
						break
			except socket.timeout:
				continue

		sock.close()
		logging.info('[RECV] Received: {} packets'.format(counter))
	def split(self, hosts, n):
		'''
			Split host range into n parts (multithreaded)
		'''
		nhosts = hosts[1] - hosts[0] # number of hosts
		nparts = nhosts/n + 1
		host_parts = []
		start = hosts[0]
		while True:
			if len(host_parts)<n-1:
				end = start + nparts
				host_parts.append((start, end))
				start = end
			else:
				host_parts.append((start, hosts[1]))
				break
		return host_parts
	def PickPort(self):
		while True:
			srcp = random.randrange(10000, 65535)
			if srcp not in self.sport:
				self.sport.append(srcp)
				break
		return srcp

def Extract(packet):
	src = socket.inet_ntoa(packet[12:16])
	srcp = struct.unpack('!H', packet[20:22])[0]
	return src, srcp

def Alive(thread_list):
	''' check if thread is alive '''
	alive = False
	for t in thread_list:
		if t.isAlive():
			alive = True
			break
	return alive
