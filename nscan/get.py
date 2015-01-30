import sys
import socket
from convert import *

def Args(args):
    '''handle arguments
    Parameters:
        args    -- arguments
    returns:
        command -- command (scan, ping, trace)
        hosts   -- hosts ('192.168.24.7', '10.0.0.0/8')
    '''
    command = 'scan'
    hosts = ''
    if len(args)==2:
        command = args[0]
        hosts = args[1]
    elif len(args)==1:
        hosts = args[0]
    else:
        raise SyntaxError('nscan.py ping example.com')  
    return hosts, command

def Hosts(host_list):
    '''
    input:
        host_list   -- hosts to scan ('10.0.0.0/8','10.0.0.0-10.255.255.255','192.168.1.23')
    output:
        hosts range -- start and end ip address (['10.0.0.0','10.255.255.255'])
    '''
    hosts = []
    if '/' in host_list:
        start, cidr = host_list.split('/')
        start = dot2dec(start) # start is the first ip address
        cidr = int(cidr)
        mask = int('1'*cidr + '0'*(32-cidr), 2)
        network_field = start & mask # fixed part
        host_field = 0xffffffff ^ mask  # variable part
        end = network_field | host_field # end is the last ip address
        hosts = [start, end+1]
    elif '-' in host_list:
        start, end = host_list.split('-')
        hosts = [dot2dec(start), dot2dec(end)+1]
    else:
        hosts = [dot2dec(host_list), dot2dec(host_list)+1]
    return hosts
    
def Ports(port_list):
    '''ports handler
    parameters:
        args    -- ports ('21-25,80,443')
    returns:
        ports   -- [[21, 25], [80], [443]]
    '''
    port_range = []
    if port_list:
        ports = port_list.replace(' ', '')
        ports = ports.split(',')
        for i in range(len(ports)):
            ports[i] = ports[i].split('-')
        for i in ports:
            if len(i)==1:
                port_range.append([int(i[0]), int(i[0])+1])
            else:
                port_range.append( [ int(i[0]), int(i[1])+1 ] )
    else:
        raise SyntaxError('-p, --port=21-25,80,443')
    return port_range

def Network():
    '''
        send a dns query and capture response packet
        Output:
            ifname: interface name
            ifaddr: interface ip address
            ifmac: interface mac address
            gateway: router mac address
    '''
    IPHI = 14   # IP header INDEX
    sniff = socket.socket(socket.AF_PACKET,
                        socket.SOCK_RAW,
                        socket.htons(0x800))
    while True:
        try:
            socket.gethostbyname('www.google.com')
            data, sa_ll = sniff.recvfrom(65535)
            if sa_ll[2] == socket.PACKET_HOST:
                break
        except:
            print 'Check your internet connection'
            sniff.close()
            sys.exit()
    sniff.close()

    ifname = sa_ll[0] # interface name
    ifmac = data[:6] # interface mac address
    gateway = data[6:12] # gateway mac address
    ifaddr = socket.inet_ntoa(data[IPHI+16:IPHI+20]) # interface ip address
    return ifname, ifaddr, ifmac, gateway

def Imports(arg):
    '''
        Returns tuple of script name and port numbers
    '''
    if arg:
        imports = {}
        arg = arg.split('+')
        for i in range(len(arg)):
            arg[i] = arg[i].split(':')
        for i in arg:
            imports[i[0]] = Ports(i[1])
        return imports
    else:
        return None

def CoolDown(arg):
    npacket, sleep = arg.split(',')
    return int(npacket), float(sleep)
