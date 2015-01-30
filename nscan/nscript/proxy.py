'''
    Nscan script that checks for SOCKS4/5 Proxies
'''
import Queue
import socket
import struct
import logging

def SendRecv(ip, port, packet):
	s = socket.socket()
	s.settimeout(3)
	try:
		s.connect((ip, port))
		s.send(packet)
		data = s.recv(65535)
	except socket.timeout:
		data = None
	s.close()
	return data

def SOCKS(ip, port):
	version = ''
	CD = '\x01' # Command: CONNECT
	DSTPORT = '\x00\x50' # Destination Port: 80
	try:
		DSTIP = socket.inet_aton(socket.gethostbyname('www.google.com'))
	except socket.gaierror:
		return version
	USERID = 'Nscan\x00'
	socks4 = struct.pack('1s1s2s4s6s', '\x04', CD, DSTPORT, DSTIP, USERID)
	socks5 = struct.pack('1s1s2s4s6s', '\x05', CD, DSTPORT, DSTIP, USERID)
	s4 = SendRecv(ip, port, socks4)
	s5 = SendRecv(ip, port, socks5)
	if s4 and s4[0]=='\x00' and s4[1]=='\x5a':
		version = '4'
	if s5 and s5[0]=='\x00' and s5[1]=='\x5a':
		version+='/5'
	return version

def run(queue, event):
	while True:
		if queue.empty() and event.isSet():
			break
		else:
			try:
				host = queue.get(False, 3)
				socks = SOCKS(host[0], host[1])
				if socks:
					logging.info('[PROXY] {}:{} | SOCKS{}'.format(host[0], host[1], socks))
			except Queue.Empty:
				pass
			except KeyboardInterrupt:
			    break
