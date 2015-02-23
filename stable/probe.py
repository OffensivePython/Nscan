import time
import Queue
import random
import socket
import struct
import logging
import threading
from convert import *
from protocol import ethernet, ip, tcp

ETH_P_IP = 0x0800 # IP protocol

NSCRIPT_PATH = 'nscript'  # NSCRIPT PATH

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
		self.sport = [] # source port
		self.smac = options.smac
		self.dmac = options.dmac
		self.ifname = options.ifname
		self.siface = options.siface
		self.diface = options.diface
		self.banner = options.banner
		self.count = options.count
		self.cooldown = options.cooldown
		self.queue = Queue.Queue()
		self.events = {
			'send': threading.Event(),
			'recv': threading.Event()}
		self.threads = {
			'send': [],
			'recv': None}
	def init(self):
		generators = []
		for h in self.hosts:
			g = Generator(h[1]-h[0])
			generators.append(g)
			t = threading.Thread(target=self.send, args=(h, self.PickPort(), g))
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
		sock = socket.socket(socket.AF_PACKET,
			socket.SOCK_RAW,
			socket.htons(ETH_P_IP))
		nhosts = hosts[1] - hosts[0]
		eth = ethernet.ETHER(mac2byte(self.smac), mac2byte(self.dmac), ETH_P_IP).pack()
		tcph = tcp.TCP(srcp, 0)
		npacket = 0
		self.events['send'].wait()
		target = hosts[0]
		while self.events['send'].isSet():
			try:
				target = hosts[0] + gen.next()
				iph = ip.IP(self.diface, dec2dot(target))
			except StopIteration:
				break
			for port_list in self.ports:
				for port in range(port_list[0], port_list[1]):
					if self.events['send'].isSet():
						tcph.dstp = port
						packet = eth + iph.pack() + tcph.pack(iph.src, iph.dst)
						sock.sendto(packet, (self.ifname, 0))
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
			socket.IPPROTO_TCP)
		sock.bind((self.diface, 0))
		sock.settimeout(5)
		self.events['recv'].wait()
		counter = 0
		while self.events['recv'].isSet():
			try:
				data, sa_ll = sock.recvfrom(65535)
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
