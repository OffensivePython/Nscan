#!/usr/bin/env python
import time
import socket
import logging
import ConfigParser
import probe
import startup
from convert import dec2dot

LOGO = r'''
    _   __                    
   / | / /_____________ _____ 
  /  |/ / ___/ ___/ __ `/ __ \
 / /|  (__  ) /__/ /_/ / / / /
/_/ |_/____/\___/\__,_/_/ /_/ 
@OffensivePython             1.0
URL: https://github.com/OffensivePython/Nscan
'''

def print_info(src, srcp, banner):
	if banner:
		s = socket.socket()
		s.settimeout(5)
		try:
			s.connect((src, srcp))
			s.send('GET\r\n\r\n')
			banner = s.recv(40)
			banner = banner.replace('\r', '')
			banner = banner.replace('\n', ' ')
			logging.info('[MAIN] {:20}|{}'.format(src+':'+str(srcp), banner))
		except (socket.timeout, socket.error):
			logging.info('[MAIN] {:20}|None'.format(src+':'+str(srcp)))
	else:
		logging.info('[MAIN] {:20}'.format(src+':'+str(srcp)))

def Alive(thread_list):
	''' check if thread is alive '''
	alive = False
	i = 0
	while True:
		alive = thread_list[i].isAlive()
		i += 1
		if alive or i==len(thread_list):
			break
	return alive

def main(options):
	scan = probe.nscan(options)
	thread, event, queue, generators = scan.init()
	nscripts = None
	if options.imports:
		nscripts = probe.ScriptEngine(options.imports)
		nscripts.Load()
	scan.run()
	start_time = time.time()
	while True:
		try:
			while not queue.empty(): # Sending thread is alive
				ip, port = queue.get()
				print_info(ip, port, options.banner)
				if nscripts:
					nscripts.Feed(ip, port)
			if not Alive(thread['send']):
				stop_time = time.time()
				time.sleep(10)
				event['recv'].clear()
				while Alive([thread['recv']]):
					time.sleep(3)
				while not queue.empty():
					ip, port = queue.get()
					print_info(ip, port, options.banner)
					if nscripts:
						nscripts.Feed(ip, port)
				if nscripts:
					nscripts.event.set()
					nscripts.Cleanup()
				break
		except KeyboardInterrupt:
			logging.info('[MAIN] Saving resume file: resume.conf')
			stop_time = time.time()
			event['send'].clear()
			event['recv'].clear()
			if nscripts:
			    nscripts.event.set()
			    nscripts.Cleanup()
			indexes = []
			for g in generators:
				indexes.append(g.suspend())
			config = ConfigParser.ConfigParser()
			cfile = open('resume.conf', 'w')
			config.add_section('NSCAN')
			config.set('NSCAN', 'hosts', options.hosts)
			config.set('NSCAN', 'ports', options.ports)
			config.set('NSCAN', 'threads', options.threads)
			config.set('NSCAN', 'imports', options.imports)
			config.set('NSCAN', 'banner', options.banner)
			config.set('NSCAN', 'count', options.count)
			config.set('NSCAN', 'output', options.output)
			config.set('NSCAN', 'indexes', indexes)
			config.set('NSCAN', 'cooldown', options.cooldown)
			config.write(cfile)
			cfile.close()
			break
	logging.info('[MAIN] Packets sent in %.01f minutes'%((stop_time-start_time)/60))
	logging.info('[MAIN] Total elapsed time: %.01f minutes'%((time.time()-start_time)/60))
	logging.info('[MAIN] Done (%s)'%time.asctime())

if __name__ == '__main__':
	parser = startup.Parser()
	options = parser.parse_args()
	nports = sum(p[1]-p[0] for p in options.ports)
	nhosts = options.hosts[1]-options.hosts[0]
	host = [dec2dot(options.hosts[0]), dec2dot(options.hosts[1])]
	print LOGO
	print 'Scanning [{} -> {}] ({} hosts/{} ports)'.format(host[0], host[1], nhosts, nports)
	if options.output:
		logging.basicConfig(level=logging.DEBUG,
			format='%(message)s',
			filename=options.output,
			filemode='w')
		console = logging.StreamHandler()
		console.setLevel(logging.INFO)
		logging.getLogger('').addHandler(console)
	else:
		logging.basicConfig(level=logging.DEBUG,
			format='%(message)s')
	logging.info('[MAIN] Starting the scan (%s)'%time.asctime())
	main(options)
