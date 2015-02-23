'''
    Example of banner grabber for Nscan
'''
import socket
import Queue
import time
import logging

def FetchBanner(ip, port):
	banner = None
	sock = socket.socket()
	sock.settimeout(5)
	try:
		sock.connect((ip, port))
		sock.send('GET\r\n\r\n')
		banner = sock.recv(65535)
		sock.close()
		banner = banner.replace('\r', '')
		banner = banner.replace('\n', ' ')
		banner = banner[:50]
	except:
		pass
	return banner

def run(queue, event):
	while True:
		if queue.empty() and event.isSet():
			break
		else:
			try:
				host = queue.get(False, 3)
				banner = FetchBanner(host[0], host[1])
				logging.info('[BANNER] {}:{} | {}'.format(host[0], host[1], banner))
			except Queue.Empty:
				pass
