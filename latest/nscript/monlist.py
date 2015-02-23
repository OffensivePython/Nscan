import Queue
import socket
import logging
# Import any module you need here

MONLIST = '\x17\x00\x02\x2a'+'\x00'*4
MIN_SIZE = 48 # Skip SYS_INFO sent by Nscan

def CheckMonlist(ip, port):
    size = None
    data = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(MONLIST, (ip, port))
        while True:
            data+= s.recvfrom(65535)[0]
            if len(data)<=len(MONLIST): # If REQUEST declined
                break
    except socket.timeout:
        if len(data)>MIN_SIZE:
            size = len(data)
    finally:
        s.close()
    return size

def run(queue, event):
    while True:
        if queue.empty() and event.isSet():
            # If the Scan is completed and the queue is empty (no more results)
            break
        else:
            try:
                ip, port = queue.get(False, 3) # Should be non-blocking
                # Do something useful with IP:PORT
                reflected = CheckMonlist(ip, port)
                if reflected:
                    logging.info('[MONLIST] {}:{} | Size:{}B'.format(ip, port, reflected))
            except KeyboardInterrupt: # Scan suspended, should exit
                break
            except Queue.Empty: # No results
                pass
